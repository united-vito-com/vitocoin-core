"""
VitoCoin Merchant Payment API
============================================================
Non-custodial, deterministic merchant payment infrastructure.

Architecture:
  • Each payment gets a unique HD-derived address (m/44'/6333'/account'/0/index)
    so the merchant never exposes their master private key
  • Payment lifecycle: PENDING → CONFIRMING → CONFIRMED | EXPIRED | UNDERPAID | OVERPAID
  • Webhook delivery with HMAC-SHA256 signature (replay-safe via timestamp + nonce)
  • Event queue for async confirmation tracking
  • Expiry, partial payment, and overpayment detection

Security notes:
  - Master xpriv is never exposed to the HTTP layer
  - Webhook secret is used only for HMAC signing — never included in payloads
  - All monetary values are in satoshis (integer arithmetic only)
  - Payment IDs are cryptographically random (32-byte hex)
"""

import hashlib
import hmac
import json
import logging
import os
import queue
import secrets
import threading
import time
import urllib.request
import urllib.error
from typing import Any, Callable, Dict, List, Optional, Tuple

from vitocoin.crypto import HDNode, mnemonic_to_seed, sha256d
from vitocoin.transaction import COIN, UTXOSet

log = logging.getLogger("VitoCoin.merchant")


# ── Payment Status ──────────────────────────────────────────────────────

class PaymentStatus:
    PENDING    = "PENDING"       # Created, awaiting funds
    CONFIRMING = "CONFIRMING"    # Funds received, waiting for confirmations
    CONFIRMED  = "CONFIRMED"     # Required confirmations reached
    EXPIRED    = "EXPIRED"       # TTL elapsed without full payment
    UNDERPAID  = "UNDERPAID"     # Received but less than required amount
    OVERPAID   = "OVERPAID"      # Received more than required (still confirmed)


# ── Default Configuration ───────────────────────────────────────────────

PAYMENT_TTL_SECONDS    = 15 * 60     # 15 minutes to pay
MIN_CONFIRMATIONS      = 1           # Confirmations before CONFIRMED
HD_COIN_TYPE           = 6333        # VitoCoin SLIP-0044 coin type
HD_PURPOSE             = 44          # BIP-44
HD_HARDENED            = 0x80000000


# ═══════════════════════════════════════════════════════════════════════
#  PAYMENT RECORD
# ═══════════════════════════════════════════════════════════════════════

class Payment:
    """
    Immutable-ish payment record. Once confirmed, status only moves forward.
    """
    __slots__ = (
        "payment_id", "merchant_id", "address", "hd_path",
        "amount_satoshi", "currency", "description",
        "status", "created_at", "expires_at",
        "received_satoshi", "tx_hashes", "confirmations",
        "webhook_url", "metadata",
        "_lock",
    )

    def __init__(self, payment_id: str, merchant_id: str, address: str, hd_path: str,
                 amount_satoshi: int, currency: str = "VITO",
                 description: str = "", webhook_url: str = "",
                 ttl: int = PAYMENT_TTL_SECONDS, metadata: dict = None):
        self.payment_id     = payment_id
        self.merchant_id    = merchant_id
        self.address        = address
        self.hd_path        = hd_path
        self.amount_satoshi = amount_satoshi
        self.currency       = currency
        self.description    = description
        self.webhook_url    = webhook_url
        self.metadata       = metadata or {}
        self.status         = PaymentStatus.PENDING
        self.created_at     = int(time.time())
        self.expires_at     = self.created_at + ttl
        self.received_satoshi = 0
        self.tx_hashes:     List[str] = []
        self.confirmations: int       = 0
        self._lock          = threading.Lock()

    # ── Status transitions ──────────────────────────────────────────────

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def apply_payment(self, amount_satoshi: int, tx_hash: str, confirmations: int) -> str:
        """
        Update payment state based on incoming funds.
        Returns the new status.
        Thread-safe.
        """
        with self._lock:
            if self.status in (PaymentStatus.CONFIRMED,):
                return self.status   # terminal state

            if tx_hash and tx_hash not in self.tx_hashes:
                self.tx_hashes.append(tx_hash)

            self.received_satoshi = amount_satoshi
            self.confirmations    = confirmations

            if self.is_expired() and amount_satoshi < self.amount_satoshi:
                self.status = PaymentStatus.EXPIRED
            elif amount_satoshi == 0:
                if self.is_expired():
                    self.status = PaymentStatus.EXPIRED
            elif amount_satoshi < self.amount_satoshi:
                self.status = PaymentStatus.UNDERPAID
            elif amount_satoshi >= self.amount_satoshi:
                if confirmations >= MIN_CONFIRMATIONS:
                    self.status = (PaymentStatus.OVERPAID
                                   if amount_satoshi > self.amount_satoshi
                                   else PaymentStatus.CONFIRMED)
                else:
                    self.status = PaymentStatus.CONFIRMING
            return self.status

    # ── Serialization ───────────────────────────────────────────────────

    def to_dict(self, include_sensitive: bool = False) -> dict:
        d = {
            "payment_id":       self.payment_id,
            "merchant_id":      self.merchant_id,
            "address":          self.address,
            "amount_satoshi":   self.amount_satoshi,
            "amount_vito":      self.amount_satoshi / COIN,
            "currency":         self.currency,
            "description":      self.description,
            "status":           self.status,
            "created_at":       self.created_at,
            "expires_at":       self.expires_at,
            "received_satoshi": self.received_satoshi,
            "received_vito":    self.received_satoshi / COIN,
            "confirmations":    self.confirmations,
            "tx_hashes":        list(self.tx_hashes),
            "metadata":         self.metadata,
        }
        if include_sensitive:
            d["hd_path"] = self.hd_path
            d["webhook_url"] = self.webhook_url
        return d


# ═══════════════════════════════════════════════════════════════════════
#  MERCHANT ACCOUNT
# ═══════════════════════════════════════════════════════════════════════

class MerchantAccount:
    """
    A single merchant's configuration: HD node + webhook secret + payment index.
    """
    def __init__(self, merchant_id: str, hd_account_node: HDNode,
                 webhook_secret: str, account_index: int = 0):
        self.merchant_id     = merchant_id
        self._hd_node        = hd_account_node   # m/44'/6333'/account'  (account-level xprv)
        self.webhook_secret  = webhook_secret
        self.account_index   = account_index
        self._payment_index  = 0
        self._index_lock     = threading.Lock()

    def next_address(self) -> Tuple[str, str, int]:
        """
        Derive next unused receiving address.
        Returns (address, hd_path, index).
        Thread-safe.
        """
        with self._index_lock:
            idx = self._payment_index
            self._payment_index += 1

        # m/44'/6333'/account'/0/idx  (change=0 for receiving)
        child = self._hd_node.derive_child(0).derive_child(idx)
        path  = f"m/{HD_PURPOSE}'/{HD_COIN_TYPE}'/{self.account_index}'/0/{idx}"
        return child.address, path, idx


# ═══════════════════════════════════════════════════════════════════════
#  WEBHOOK DELIVERY
# ═══════════════════════════════════════════════════════════════════════

def _webhook_signature(secret: str, payload_bytes: bytes, timestamp: int, nonce: str) -> str:
    """
    HMAC-SHA256 over: timestamp + "." + nonce + "." + payload_hex
    Returns hex digest.
    Replay-safe: timestamp + nonce must be unique per delivery.
    """
    signing_input = f"{timestamp}.{nonce}.".encode() + payload_bytes
    return hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).hexdigest()


def _deliver_webhook(url: str, secret: str, event: str, payment: Payment,
                     max_retries: int = 3) -> bool:
    """
    POST webhook to `url` with HMAC-SHA256 signature header.
    Returns True on successful delivery (2xx response).
    Retries with exponential backoff.
    """
    if not url:
        return False

    payload = json.dumps({
        "event":      event,
        "payment_id": payment.payment_id,
        "status":     payment.status,
        "amount_satoshi":   payment.amount_satoshi,
        "received_satoshi": payment.received_satoshi,
        "tx_hashes":  payment.tx_hashes,
        "confirmations": payment.confirmations,
        "timestamp":  int(time.time()),
    }, separators=(",", ":")).encode("utf-8")

    timestamp = int(time.time())
    nonce     = secrets.token_hex(8)
    sig       = _webhook_signature(secret, payload, timestamp, nonce)

    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(
                url,
                data    = payload,
                headers = {
                    "Content-Type":          "application/json",
                    "X-VitoCoin-Signature":  sig,
                    "X-VitoCoin-Timestamp":  str(timestamp),
                    "X-VitoCoin-Nonce":      nonce,
                    "User-Agent":            "VitoCoin-Webhook/2.0",
                },
                method  = "POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if 200 <= resp.status < 300:
                    log.info("Webhook delivered: %s → %s (attempt %d)",
                             payment.payment_id[:12], url, attempt + 1)
                    return True
                log.warning("Webhook HTTP %d for %s (attempt %d)",
                            resp.status, payment.payment_id[:12], attempt + 1)
        except urllib.error.URLError as e:
            log.warning("Webhook delivery failed for %s (attempt %d): %s",
                        payment.payment_id[:12], attempt + 1, e)
        except Exception as e:
            log.error("Webhook unexpected error for %s: %s", payment.payment_id[:12], e)
            break   # don't retry on unexpected errors

        if attempt < max_retries - 1:
            time.sleep(2 ** attempt)   # 1s, 2s backoff

    log.error("Webhook delivery FAILED after %d attempts: %s", max_retries, url)
    return False


# ═══════════════════════════════════════════════════════════════════════
#  MERCHANT PAYMENT ENGINE
# ═══════════════════════════════════════════════════════════════════════

class MerchantEngine:
    """
    Central payment engine.

    - Manages multiple merchant accounts (multi-tenant)
    - Creates payments with deterministic HD addresses
    - Monitors blockchain for incoming funds
    - Fires webhook events on status changes
    - Event queue for async processing

    Usage:
        engine = MerchantEngine(blockchain, utxo_set)
        engine.register_merchant("shop1", hd_node, webhook_secret="...")
        payment = engine.create_payment("shop1", 500000, "Order #123", webhook_url="...")
        engine.start()  # starts background confirmation monitor
    """

    def __init__(self, utxo_set: UTXOSet, chain_height_fn: Callable[[], int]):
        self._utxo           = utxo_set
        self._chain_height   = chain_height_fn   # callable → current block height
        self._merchants:  Dict[str, MerchantAccount] = {}
        self._payments:   Dict[str, Payment]          = {}
        self._addr_index: Dict[str, str]              = {}   # address → payment_id
        self._lock        = threading.RLock()
        # Webhook delivery queue (runs in background thread)
        self._webhook_q:  queue.Queue = queue.Queue()
        self._running     = False

    # ── Merchant registration ────────────────────────────────────────────

    def register_merchant(self, merchant_id: str, hd_account_node: HDNode,
                          webhook_secret: str, account_index: int = 0) -> None:
        """Register a merchant account with its HD account node and webhook secret."""
        with self._lock:
            self._merchants[merchant_id] = MerchantAccount(
                merchant_id, hd_account_node, webhook_secret, account_index
            )
        log.info("Merchant registered: %s", merchant_id)

    # ── Payment creation ─────────────────────────────────────────────────

    def create_payment(self, merchant_id: str, amount_satoshi: int,
                       description: str = "", webhook_url: str = "",
                       ttl: int = PAYMENT_TTL_SECONDS,
                       metadata: dict = None) -> Payment:
        """
        Create a new payment request.
        Returns a Payment object with a unique address.
        """
        if amount_satoshi <= 0:
            raise ValueError("amount_satoshi must be positive")
        if amount_satoshi > 21_000_000 * COIN:
            raise ValueError("amount_satoshi exceeds total supply")

        with self._lock:
            merchant = self._merchants.get(merchant_id)
            if merchant is None:
                raise ValueError(f"Unknown merchant: {merchant_id}")

            address, hd_path, _ = merchant.next_address()
            payment_id          = secrets.token_hex(16)

            payment = Payment(
                payment_id     = payment_id,
                merchant_id    = merchant_id,
                address        = address,
                hd_path        = hd_path,
                amount_satoshi = amount_satoshi,
                description    = description,
                webhook_url    = webhook_url,
                ttl            = ttl,
                metadata       = metadata or {},
            )
            self._payments[payment_id]   = payment
            self._addr_index[address]    = payment_id

        log.info("Payment created: %s → %s (%d sat)", payment_id[:12], address, amount_satoshi)
        return payment

    # ── Payment lookup ───────────────────────────────────────────────────

    def get_payment(self, payment_id: str) -> Optional[Payment]:
        return self._payments.get(payment_id)

    def get_payment_by_address(self, address: str) -> Optional[Payment]:
        pid = self._addr_index.get(address)
        return self._payments.get(pid) if pid else None

    def list_payments(self, merchant_id: str, status: str = None,
                      limit: int = 100, offset: int = 0) -> List[Payment]:
        with self._lock:
            results = [
                p for p in self._payments.values()
                if p.merchant_id == merchant_id and (status is None or p.status == status)
            ]
        results.sort(key=lambda p: p.created_at, reverse=True)
        return results[offset: offset + limit]

    # ── Payment verification ─────────────────────────────────────────────

    def verify_payment(self, payment_id: str) -> Tuple[bool, str, dict]:
        """
        Check current UTXO state for a payment address.
        Returns (is_paid, message, details_dict).
        """
        payment = self.get_payment(payment_id)
        if payment is None:
            return False, "Payment not found", {}

        balance   = self._utxo.balance(payment.address)
        height    = self._chain_height()
        utxos     = self._utxo.utxos_for_address(payment.address)
        tx_hashes = list({txid for txid, _, _ in utxos})
        confs     = self._min_confirmations(utxos, height)

        new_status = payment.apply_payment(balance, tx_hashes[0] if tx_hashes else "", confs)

        # Expiry override for zero-balance pending payments
        if new_status == PaymentStatus.PENDING and payment.is_expired():
            payment.status = PaymentStatus.EXPIRED
            new_status     = PaymentStatus.EXPIRED

        details = {
            "payment_id":       payment_id,
            "address":          payment.address,
            "amount_required":  payment.amount_satoshi,
            "amount_received":  balance,
            "difference":       balance - payment.amount_satoshi,
            "confirmations":    confs,
            "status":           new_status,
            "tx_hashes":        tx_hashes,
            "expires_at":       payment.expires_at,
            "is_expired":       payment.is_expired(),
        }
        is_paid = new_status in (PaymentStatus.CONFIRMED, PaymentStatus.OVERPAID)
        return is_paid, new_status, details

    # ── Webhook signature verification (for merchant-side verification) ──

    @staticmethod
    def verify_webhook_signature(secret: str, payload_bytes: bytes,
                                 timestamp: int, nonce: str,
                                 received_sig: str) -> bool:
        """
        Verify a webhook signature.
        Call this on the receiving end (merchant server) to validate delivery.
        Returns True if signature matches and timestamp is within 5 minutes.
        """
        # Replay protection: reject if timestamp > 5 minutes old
        if abs(time.time() - timestamp) > 300:
            return False
        expected = _webhook_signature(secret, payload_bytes, timestamp, nonce)
        return hmac.compare_digest(expected, received_sig)

    # ── Confirmation monitor ─────────────────────────────────────────────

    def start(self) -> None:
        """Start background threads: confirmation monitor + webhook delivery."""
        self._running = True
        threading.Thread(target=self._confirm_loop, daemon=True,
                         name="merchant-confirm").start()
        threading.Thread(target=self._webhook_worker, daemon=True,
                         name="merchant-webhook").start()
        log.info("MerchantEngine started")

    def stop(self) -> None:
        self._running = False

    def _confirm_loop(self) -> None:
        """
        Every 15 seconds: check all pending/confirming payments against UTXO set.
        Fire webhook events on state transitions.
        """
        WATCH_STATUSES = {PaymentStatus.PENDING, PaymentStatus.CONFIRMING,
                          PaymentStatus.UNDERPAID}
        while self._running:
            time.sleep(15)
            try:
                with self._lock:
                    pending = [p for p in self._payments.values()
                               if p.status in WATCH_STATUSES]
                for payment in pending:
                    prev_status = payment.status
                    balance     = self._utxo.balance(payment.address)
                    height      = self._chain_height()

                    # Get confirmations for this payment's UTXOs
                    utxos     = self._utxo.utxos_for_address(payment.address)
                    tx_hashes = list({txid for txid, _, _ in utxos})
                    confs     = self._min_confirmations(utxos, height)

                    new_status = payment.apply_payment(
                        balance,
                        tx_hashes[0] if tx_hashes else "",
                        confs,
                    )

                    # Expiry check for zero-balance payments
                    if new_status == PaymentStatus.PENDING and payment.is_expired():
                        payment.status = PaymentStatus.EXPIRED
                        new_status     = PaymentStatus.EXPIRED

                    if new_status != prev_status:
                        log.info("Payment %s: %s → %s",
                                 payment.payment_id[:12], prev_status, new_status)
                        self._enqueue_webhook(payment, f"payment.{new_status.lower()}")
            except Exception as e:
                log.error("Confirm loop error: %s", e)

    def _min_confirmations(self, utxos: list, current_height: int) -> int:
        """Return minimum confirmations for a list of UTXOs."""
        if not utxos:
            return 0
        min_confs = None
        for txid, idx, _ in utxos:
            entry = self._utxo._utxos.get(f"{txid}:{idx}")
            if entry is not None:
                _, blk_h, _ = entry
                c = max(0, current_height - blk_h + 1)
                min_confs = c if min_confs is None else min(min_confs, c)
        return min_confs or 0

    # ── Webhook queue ────────────────────────────────────────────────────

    def _enqueue_webhook(self, payment: Payment, event: str) -> None:
        if payment.webhook_url:
            self._webhook_q.put((payment, event))

    def _webhook_worker(self) -> None:
        """Background thread: drain webhook queue, deliver with retry."""
        while self._running:
            try:
                payment, event = self._webhook_q.get(timeout=5)
                with self._lock:
                    merchant = self._merchants.get(payment.merchant_id)
                if merchant:
                    threading.Thread(
                        target=_deliver_webhook,
                        args=(payment.webhook_url, merchant.webhook_secret,
                              event, payment),
                        daemon=True,
                    ).start()
            except queue.Empty:
                continue
            except Exception as e:
                log.error("Webhook worker error: %s", e)

    # ── Statistics ───────────────────────────────────────────────────────

    def stats(self, merchant_id: str = None) -> dict:
        with self._lock:
            payments = [p for p in self._payments.values()
                        if merchant_id is None or p.merchant_id == merchant_id]
        by_status: Dict[str, int] = {}
        total_received = 0
        for p in payments:
            by_status[p.status] = by_status.get(p.status, 0) + 1
            total_received      += p.received_satoshi
        return {
            "total_payments":    len(payments),
            "by_status":         by_status,
            "total_received_satoshi": total_received,
            "total_received_vito":    total_received / COIN,
            "webhook_queue_depth":    self._webhook_q.qsize(),
        }


# ═══════════════════════════════════════════════════════════════════════
#  FACTORY
# ═══════════════════════════════════════════════════════════════════════

def create_merchant_engine(utxo_set: UTXOSet,
                           chain_height_fn: Callable[[], int]) -> MerchantEngine:
    """Create and return a MerchantEngine (not started yet)."""
    return MerchantEngine(utxo_set, chain_height_fn)


def register_merchant_from_mnemonic(engine: MerchantEngine,
                                    merchant_id: str,
                                    mnemonic: str,
                                    webhook_secret: str,
                                    account_index: int = 0,
                                    passphrase: str = "") -> None:
    """
    Convenience: register a merchant from a BIP-39 mnemonic.
    Derives account node at m/44'/6333'/account'.
    """
    seed         = mnemonic_to_seed(mnemonic, passphrase)
    master       = HDNode.from_seed(seed)
    account_node = master.derive_path(
        f"m/{HD_PURPOSE}'/{HD_COIN_TYPE}'/{account_index}'"
    )
    engine.register_merchant(merchant_id, account_node, webhook_secret, account_index)
