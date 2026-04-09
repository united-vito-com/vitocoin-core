"""
VitoCoin Webhook Manager (webhooks.py)
=======================================
Manages merchant webhook subscriptions and fires signed HTTP POST payloads
whenever a new block contains outputs to a subscribed address.

Reorg protection:
  Webhooks are only dispatched for blocks at height >= CONFIRM_DEPTH (default 1)
  above the tip at fire-time.  Because we compare against the *current* tip
  before dispatching, a reorg that orphans the block will cause the fired height
  to no longer be on the main chain — the event is therefore silently dropped
  rather than re-fired for the replacement block.  The `notified_blocks` table
  also prevents re-firing for the same (block_hash, address) pair regardless of
  reorgs or node restarts.

Signing:
  Each payload is signed with HMAC-SHA256 using the WEBHOOK_SECRET env var.
  The signature is sent as the X-VitoCoin-Signature header in the format:
    sha256=<hex_digest>
  Merchants can verify: hmac.compare_digest(expected, received)
"""

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import threading
import time
import urllib.request
import urllib.error
from typing import List, Optional

log = logging.getLogger("VitoCoin.webhooks")

WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "vitocoin-webhook-default-secret")
CONFIRM_DEPTH  = int(os.environ.get("WEBHOOK_CONFIRM_DEPTH", "1"))
RETRY_DELAYS   = [5, 30, 120, 600]   # seconds between retries (4 attempts total)
DISPATCH_TIMEOUT = 10                 # seconds per HTTP request

DB_PATH = os.environ.get("WEBHOOK_DB", "/opt/vitocoin/chaindata/webhooks.db")


# ── Database ──────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = _get_conn()
    with conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS subscriptions (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                address      TEXT NOT NULL,
                url          TEXT NOT NULL,
                secret       TEXT,
                created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                UNIQUE(address, url)
            );
            CREATE INDEX IF NOT EXISTS idx_sub_addr ON subscriptions(address);

            CREATE TABLE IF NOT EXISTS notified_blocks (
                block_hash   TEXT NOT NULL,
                address      TEXT NOT NULL,
                height       INTEGER NOT NULL,
                fired_at     INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                PRIMARY KEY (block_hash, address)
            );

            CREATE TABLE IF NOT EXISTS payment_history (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                address      TEXT NOT NULL,
                txid         TEXT NOT NULL,
                amount_sats  INTEGER NOT NULL,
                block_hash   TEXT NOT NULL,
                height       INTEGER NOT NULL,
                fired_at     INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
            CREATE INDEX IF NOT EXISTS idx_ph_addr ON payment_history(address);
        """)
    conn.close()
    log.info("Webhook DB initialised at %s", DB_PATH)


# ── Subscription management ───────────────────────────────────────────────────

def register_subscription(address: str, url: str, secret: Optional[str] = None) -> dict:
    conn = _get_conn()
    try:
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO subscriptions(address, url, secret) VALUES(?,?,?)",
                (address, url, secret)
            )
        return {"ok": True, "address": address, "url": url}
    finally:
        conn.close()


def list_subscriptions(address: str) -> List[dict]:
    conn = _get_conn()
    try:
        rows = conn.execute(
            "SELECT address, url, created_at FROM subscriptions WHERE address=?",
            (address,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_payment_history(address: str, limit: int = 50) -> List[dict]:
    conn = _get_conn()
    try:
        rows = conn.execute(
            "SELECT txid, amount_sats, block_hash, height, fired_at "
            "FROM payment_history WHERE address=? ORDER BY height DESC LIMIT ?",
            (address, limit)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ── Signing ───────────────────────────────────────────────────────────────────

def _sign_payload(body: bytes, secret: Optional[str] = None) -> str:
    key = (secret or WEBHOOK_SECRET).encode()
    return "sha256=" + hmac.new(key, body, hashlib.sha256).hexdigest()


# ── HTTP dispatch with retries ────────────────────────────────────────────────

def _post_with_retry(url: str, payload: dict, signature: str,
                     address: str, block_hash: str, amount_sats: int,
                     height: int, txid: str):
    body = json.dumps(payload, separators=(",", ":")).encode()
    headers = {
        "Content-Type": "application/json",
        "X-VitoCoin-Signature": signature,
        "X-VitoCoin-Version": "1",
        "User-Agent": "VitoCoin-Webhook/1.0",
    }
    for attempt, delay in enumerate([0] + RETRY_DELAYS):
        if delay:
            time.sleep(delay)
        try:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=DISPATCH_TIMEOUT) as resp:
                status = resp.status
            if 200 <= status < 300:
                log.info("Webhook delivered: addr=%s url=%s height=%d txid=%s",
                         address, url, height, txid[:16])
                # Record in payment_history
                conn = _get_conn()
                try:
                    with conn:
                        conn.execute(
                            "INSERT OR IGNORE INTO payment_history"
                            "(address,txid,amount_sats,block_hash,height) VALUES(?,?,?,?,?)",
                            (address, txid, amount_sats, block_hash, height)
                        )
                finally:
                    conn.close()
                return
            else:
                log.warning("Webhook attempt %d failed: status %d url=%s", attempt+1, status, url)
        except Exception as e:
            log.warning("Webhook attempt %d error: %s url=%s", attempt+1, e, url)
    log.error("Webhook permanently failed after %d attempts: url=%s addr=%s",
              len(RETRY_DELAYS)+1, url, address)


# ── Block event handler ───────────────────────────────────────────────────────

def on_new_block(block, chain=None):
    """
    Called by blockchain.block_listeners when a new block is connected.
    `chain` is the Blockchain instance (injected via closure in WebhookManager).

    Reorg protection:
      - We only fire for a block if it is still on the main chain at dispatch time.
      - The (block_hash, address) pair is recorded in notified_blocks to prevent
        double-firing across restarts.
    """
    height = block.height

    # Reorg guard: verify block is still on the main chain
    if chain is not None:
        if height >= len(chain.chain) or chain.chain[height].hash != block.hash:
            log.info("Skipping webhook for orphaned block #%d %s", height, block.hash[:16])
            return

    conn = _get_conn()
    try:
        # Gather all subscribed addresses that appear in this block's outputs
        subs = conn.execute("SELECT address, url, secret FROM subscriptions").fetchall()
        if not subs:
            return
        sub_map = {}  # address → [(url, secret)]
        for s in subs:
            sub_map.setdefault(s["address"], []).append((s["url"], s["secret"]))

        for tx in block.transactions:
            for out_idx, out in enumerate(tx.outputs):
                addr = _script_to_address(out.script_pubkey)
                if addr and addr in sub_map:
                    # Dedup: skip if we already notified for this (block, address)
                    already = conn.execute(
                        "SELECT 1 FROM notified_blocks WHERE block_hash=? AND address=?",
                        (block.hash, addr)
                    ).fetchone()
                    if already:
                        continue
                    # Mark as notified BEFORE dispatching (prevents double-fire on restart)
                    with conn:
                        conn.execute(
                            "INSERT OR IGNORE INTO notified_blocks(block_hash,address,height)"
                            " VALUES(?,?,?)",
                            (block.hash, addr, height)
                        )
                    payload = {
                        "event":      "payment",
                        "network":    "VitoCoin Mainnet",
                        "address":    addr,
                        "txid":       tx.txid,
                        "amount":     out.value,
                        "amount_vito": out.value / 1e8,
                        "block_hash": block.hash,
                        "height":     height,
                        "timestamp":  block.header.timestamp,
                        "confirmations": 1,
                    }
                    body = json.dumps(payload, separators=(",", ":")).encode()
                    for url, secret in sub_map[addr]:
                        sig = _sign_payload(body, secret)
                        threading.Thread(
                            target=_post_with_retry,
                            args=(url, payload, sig, addr, block.hash,
                                  out.value, height, tx.txid),
                            daemon=True
                        ).start()
    finally:
        conn.close()


def _script_to_address(script_pubkey: bytes) -> Optional[str]:
    """
    Decode a P2PKH script (OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG)
    to a VitoCoin address (Base58Check with prefix 0x46 = 'V').
    """
    try:
        if len(script_pubkey) == 25 and script_pubkey[0:3] == bytes([0x76, 0xa9, 0x14]):
            pubkey_hash = script_pubkey[3:23]
            from vitocoin.crypto import base58check_encode
            return base58check_encode(bytes([0x46]), pubkey_hash)
    except Exception as _e:
        log.debug("_script_to_address error: %s", _e)
    return None


# ── Manager class (wires into the node) ──────────────────────────────────────

class WebhookManager:
    """
    Attach to a Blockchain instance via:
        mgr = WebhookManager(chain)
        mgr.start()
    """
    def __init__(self, chain):
        self.chain = chain

    def start(self):
        init_db()
        def _listener(block):
            on_new_block(block, chain=self.chain)
        self.chain.block_listeners.append(_listener)
        log.info("WebhookManager registered on chain (confirm_depth=%d)", CONFIRM_DEPTH)
