"""
VitoCoin REST API — Block Explorer + Node Control
============================================================
Production-grade HTTP API with:
  • Full block explorer (blocks, transactions, addresses, UTXOs)
  • Node status and peer management
  • Raw transaction submission + broadcast
  • Mining control and getblocktemplate
  • Rate limiting per IP (sliding window)
  • CORS support
  • Request size limits
  • Structured error responses  {"error": "...", "code": <N>}
  • /health   — liveness probe
  • /healthz  — same as /health (k8s convention)
  • /metrics  — Prometheus-compatible plaintext metrics

Thread-safety notes:
  • All mutable state (blockchain, miner, p2p) is passed to run_api()
    and stored on the server instance — NOT as class-level attributes.
  • Each request handler receives these via self.server.app_*.
  • Blockchain itself is guarded by its own RLock; the API adds no extra lock.
"""

import hashlib
import hmac
import ipaddress
import json
import collections
import ipaddress

# ─── Miner Registry ──────────────────────────────────────────────────────────
# Tracks external miners connecting to /mining/template + /mining/submit
_MINER_REGISTRY = {}          # ip -> {wallet, first_seen, last_seen, shares, blocks}
_MINER_HASHRATE  = {}         # ip -> [(ts, hashrate_hps), ...]  rolling 60s window
_MINER_BAN_LIST  = set()      # banned IPs
_REQUEST_COUNTER = {}         # ip -> [timestamps]  for rate limiting

# ─── Rate limiter ─────────────────────────────────────────────────────────────
_RL_WINDOW   = 60    # seconds
_RL_MAX_GET  = 300   # max GET requests per window per IP
_RL_MAX_POST = 60    # max POST requests per window per IP

TRUSTED_PROXIES = {'127.0.0.1'}  # only trust XFF from local Nginx proxy (F-03)

def _get_client_ip(handler):
    """
    Only trust X-Forwarded-For when the TCP connection comes
    from a known proxy (Nginx on localhost). Any other caller
    gets their real TCP address. Prevents IP spoofing via a
    forged XFF header from external clients (F-03).
    """
    tcp_peer = handler.client_address[0]
    if tcp_peer in TRUSTED_PROXIES:
        xff = handler.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
    return tcp_peer

def _rate_limit(handler, method="GET"):
    import time as _time
    ip = _get_client_ip(handler)
    if ip in _MINER_BAN_LIST:
        return False
    now = _time.time()
    bucket = _REQUEST_COUNTER.setdefault(ip, [])
    # Evict old entries
    _REQUEST_COUNTER[ip] = [t for t in bucket if now - t < _RL_WINDOW]
    limit = _RL_MAX_POST if method == "POST" else _RL_MAX_GET
    if len(_REQUEST_COUNTER[ip]) >= limit:
        return False
    _REQUEST_COUNTER[ip].append(now)
    return True

def _register_miner(ip, wallet, hashrate_hps=0):
    import time as _time
    now = _time.time()
    if ip not in _MINER_REGISTRY:
        _MINER_REGISTRY[ip] = {"wallet": wallet, "first_seen": now, "last_seen": now,
                                "shares": 0, "blocks": 0, "hashrate_hps": 0}
    m = _MINER_REGISTRY[ip]
    m["last_seen"] = now
    m["wallet"] = wallet
    if hashrate_hps:
        m["hashrate_hps"] = hashrate_hps
        window = _MINER_HASHRATE.setdefault(ip, [])
        window.append((now, hashrate_hps))
        _MINER_HASHRATE[ip] = [(t, h) for t, h in window if now - t < 60]
    # Auto-ban: single miner claiming > 80% of network hashrate AND > 5 Mh/s
    try:
        network_hr = sum(v["hashrate_hps"] for v in _MINER_REGISTRY.values())
        if network_hr > 0 and hashrate_hps / network_hr > 0.85 and hashrate_hps > 5_000_000:
            _MINER_BAN_LIST.add(ip)
    except Exception:
        pass

def _get_network_stats(chain):
    import time as _time
    now = _time.time()
    active_miners = {ip: m for ip, m in _MINER_REGISTRY.items()
                     if now - m["last_seen"] < 3600}   # active = seen in last hour
    total_ext_hr = sum(m.get("hashrate_hps", 0) for m in active_miners.values())
    return {
        "active_external_miners": len(active_miners),
        "total_external_hashrate_hps": total_ext_hr,
        "banned_ips": len(_MINER_BAN_LIST),
        "request_ips_tracked": len(_REQUEST_COUNTER),
    }

import logging
import mimetypes
import os
import re
import secrets
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Optional, Dict, Set
from urllib.parse import urlparse, parse_qs

from vitocoin.blockchain import Blockchain, Block, BlockHeader, VERSION, block_subsidy
from vitocoin.transaction import Transaction, TxInput, TxOutput, COIN
from vitocoin.miner import Miner, getblocktemplate
from vitocoin.network import P2PNode
from vitocoin.merchant import MerchantEngine, PaymentStatus
try:
    from vitocoin.webhooks import WebhookManager, register_subscription, list_subscriptions, get_payment_history
    _WEBHOOKS_AVAILABLE = True
except ImportError:
    _WEBHOOKS_AVAILABLE = False
    WebhookManager = None

log = logging.getLogger("VitoCoin.api")

# ── Private / reserved IP ranges (SSRF protection) ─────────────────────
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("100.64.0.0/10"),   # shared address space
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def _is_private_ip(host: str) -> bool:
    """Return True if host resolves to a private/reserved address."""
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        # hostname — block localhost and local variants
        low = host.lower()
        return low in ("localhost", "ip6-localhost", "ip6-loopback") or low.endswith(".local")

def _validate_peer_host(host: str) -> str:
    """Validate peer host is not private/empty. Returns host or raises ValueError."""
    if not host or len(host) > 253:
        raise ValueError("Invalid or empty host")
    # Must look like a valid IP or hostname
    if not re.match(r'^[a-zA-Z0-9.\-:\[\]]+$', host):
        raise ValueError("Host contains invalid characters")
    if _is_private_ip(host):
        raise ValueError("Connection to private/reserved IP addresses is not allowed")
    return host


# ── Validation helpers ─────────────────────────────────────────────────

_HEX64_RE = re.compile(r'^[0-9a-fA-F]{64}$')
_ADDR_RE   = re.compile(r'^[1-9A-HJ-NP-Za-km-z]{25,34}$')   # Base58Check


def _require_hex64(value: str, name: str) -> str:
    if not _HEX64_RE.match(value):
        raise ValueError(f"Invalid {name}: must be 64 hex characters")
    return value.lower()


def _require_address(value: str, name: str) -> str:
    if not _ADDR_RE.match(value):
        raise ValueError(f"Invalid {name}: not a valid Base58Check address")
    return value


def _int_param(qs: dict, name: str, default: int, lo: int, hi: int) -> int:
    raw = qs.get(name, [str(default)])[0]
    try:
        v = int(raw)
    except ValueError:
        raise ValueError(f"Query param '{name}' must be an integer")
    if not (lo <= v <= hi):
        raise ValueError(f"Query param '{name}' must be between {lo} and {hi}")
    return v


# ── Rate limiter ───────────────────────────────────────────────────────

class RateLimiter:
    """
    Sliding-window rate limiter.
    Separate per-bucket limits (e.g. 'read', 'tx', 'admin') per IP.
    A background thread auto-cleans stale entries every 60 seconds.
    """
    # Limits per IP per minute per bucket
    BUCKET_LIMITS: Dict[str, int] = {
        "read":  300,   # block explorer, status
        "tx":      5,   # transaction submission (strict — prevents spam)
        "admin":  10,   # /peers/connect
        "global": 600,  # absolute ceiling across all buckets
    }

    def __init__(self, max_per_minute: Optional[int] = None):
        # When max_per_minute is given, override the 'global' bucket default
        if max_per_minute is not None:
            self.BUCKET_LIMITS = dict(self.BUCKET_LIMITS)   # copy class-level dict
            self.BUCKET_LIMITS["global"] = max_per_minute
            # Also set the default bucket to the same limit so check(ip) works
            self.BUCKET_LIMITS["read"] = max_per_minute
        self._counts: Dict[str, Dict[str, list]] = {}  # ip → bucket → [timestamps]
        self._lock   = threading.Lock()
        # Start background cleanup thread
        t = threading.Thread(target=self._cleanup_loop, daemon=True)
        t.start()

    def check(self, ip: str, bucket: str = "read") -> bool:
        now    = time.time()
        window = 60.0
        limit  = self.BUCKET_LIMITS.get(bucket, 120)
        with self._lock:
            ip_data = self._counts.setdefault(ip, {})
            calls = [t for t in ip_data.get(bucket, []) if now - t < window]
            if len(calls) >= limit:
                return False
            calls.append(now)
            ip_data[bucket] = calls
            # Also enforce global ceiling
            all_calls = sum(len(v) for v in ip_data.values())
            if all_calls > self.BUCKET_LIMITS["global"]:
                return False
            return True

    def cleanup(self) -> None:
        """Evict stale entries — called automatically every 60 s."""
        now = time.time()
        with self._lock:
            for ip in list(self._counts.keys()):
                for bucket in list(self._counts[ip].keys()):
                    self._counts[ip][bucket] = [t for t in self._counts[ip][bucket]
                                                if now - t < 60.0]
                # Remove IPs with no remaining entries
                if not any(self._counts[ip].values()):
                    del self._counts[ip]

    def _cleanup_loop(self):
        while True:
            time.sleep(60)
            try:
                self.cleanup()
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════
#  REQUEST HANDLER
# ═══════════════════════════════════════════════════════════════════════

class VitoCoinAPI(BaseHTTPRequestHandler):
    """
    REST API endpoints:

    Node:
      GET /status              Node info, sync state, network
      GET /health              Liveness probe (200 OK)
      GET /healthz             Same (k8s convention)
      GET /metrics             Prometheus plaintext metrics
      GET /peers               Connected peer list
      POST /peers/connect      Connect to a new peer

    Blockchain:
      GET /blocks              Recent blocks (paginated: ?limit=20&offset=0)
      GET /block/<height|hash> Block by height (int) or hash (64 hex)
      GET /tx/<txid>           Transaction by ID
      GET /address/<addr>      Address balance + UTXO list (?limit=200&offset=0)
      GET /utxo/<txid>/<idx>   Single UTXO lookup
      GET /mempool             Pending transactions
      GET /mempool/stats       Mempool fee-rate statistics
      GET /mempool/<txid>      Specific mempool tx
      GET /fee-estimate        Fee rate percentiles (p25/p50/p75 sat/byte)
      GET /supply              Circulating supply info

    Mining:
      GET /mining/template     getblocktemplate (BIP-22)
      GET /mining/status       Miner stats

    Submit:
      POST /tx                 Broadcast raw transaction (JSON)
      POST /tx/broadcast       Alias for POST /tx
    """

    MAX_BODY = 1_000_000   # 1 MB max request body

    # ── Helpers to reach app state (stored on server, NOT class-level) ──

    @property
    def _chain(self) -> Blockchain:
        return self.server.app_blockchain

    @property
    def _miner(self) -> Optional[Miner]:
        return self.server.app_miner

    @property
    def _p2p(self) -> Optional[P2PNode]:
        return self.server.app_p2p

    @property
    def _start_time(self) -> float:
        return self.server.app_start_time

    @property
    def _rate_limiter(self) -> RateLimiter:
        return self.server.app_rate_limiter

    @property
    def _merchant(self) -> Optional[MerchantEngine]:
        return getattr(self.server, "app_merchant", None)

    def log_message(self, fmt, *args):
        pass   # Delegate to our logger

    # ── API key auth ────────────────────────────────────────────────────

    @property
    def _api_keys(self) -> Set[str]:
        return getattr(self.server, "app_api_keys", set())

    def _check_auth(self, required: bool = False) -> bool:
        """
        Check Bearer token / API key from Authorization header.
        If no API keys are configured, auth is disabled (open node mode).
        If keys are configured and required=True, request must supply a valid key.
        Always returns True if no keys are configured.
        """
        keys = self._api_keys
        if not keys:
            return True   # Open mode
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:].strip()
            # constant-time comparison to prevent timing attacks
            return any(hmac.compare_digest(token, k) for k in keys)
        if required:
            return False
        return False   # Keys configured but none provided

    # ── CORS + OPTIONS ─────────────────────────────────────────────────

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "https://vitocoin.com")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Max-Age",       "86400")

    # ── Security headers ────────────────────────────────────────────────

    def _security_headers(self):
        self.send_header("X-Content-Type-Options",  "nosniff")
        self.send_header("X-Frame-Options",          "DENY")
        self.send_header("Referrer-Policy",          "no-referrer")

    # ── Static file serving ────────────────────────────────────────────

    def _serve_static(self, url_path: str) -> bool:
        """Serve wallet/ static files. Returns True if handled."""
        static_dir = getattr(self.server, "app_static_dir", None)
        if not static_dir or not os.path.isdir(static_dir):
            return False
        p = url_path.split("?")[0].rstrip("/") or "/"
        # Route mapping
        if p in ("/", ""):
            rel = "index.html"
        elif p.startswith("/wallet/"):
            rel = p[len("/wallet/"):]
        elif p == "/wallet":
            rel = "index.html"
        else:
            return False
        # Prevent path traversal
        real_static = os.path.realpath(static_dir)
        abs_path = os.path.realpath(os.path.join(static_dir, rel))
        if not abs_path.startswith(real_static + os.sep) and abs_path != real_static:
            return False
        if not os.path.isfile(abs_path):
            return False
        mime, _ = mimetypes.guess_type(abs_path)
        mime = mime or "application/octet-stream"
        try:
            with open(abs_path, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Access-Control-Allow-Origin", "https://vitocoin.com")
            self.end_headers()
            self.wfile.write(data)
            return True
        except Exception as exc:
            log.warning("Static serve error %s: %s", abs_path, exc)
            return False

    # ── GET ────────────────────────────────────────────────────────────

    def do_GET(self):
        client_ip = self.client_address[0]
        if not self._rate_limiter.check(client_ip, "read"):
            return self._error(429, "Rate limit exceeded — try again in 60 seconds")

        # Serve wallet static files (/, /wallet, /wallet/*)
        if self._serve_static(self.path):
            return

        parsed = urlparse(self.path)
        parts  = [p for p in parsed.path.strip("/").split("/") if p]
        qs     = parse_qs(parsed.query)


        # ── /events  (Server-Sent Events — real-time push) ────────────
        if parsed.path.rstrip("/") in ("/events", "/stream"):
            return self._handle_sse()
        try:
            body = self._route_get(parts, qs)
            if body is None:
                return self._error(404, "Endpoint not found")
            self._ok(body)
        except ValueError as e:
            self._error(400, str(e))
        except Exception as e:
            log.error("API GET error on %s: %s", self.path, e, exc_info=True)
            self._error(500, "Internal server error")

    def _route_get(self, parts: list, qs: dict) -> Optional[Any]:
        chain = self._chain
        miner = self._miner
        p2p   = self._p2p

        if not parts:
            return {"name": "VitoCoin", "version": VERSION}

        # ── /health or /healthz ───────────────────────────────────────
        if parts[0] in ("health", "healthz") and len(parts) == 1:
            return {
                "status":   "ok",
                "height":   chain.height,
                "uptime_s": int(time.time() - self._start_time),
            }

        # ── /metrics ─────────────────────────────────────────────────
        if parts == ["network-stats"]:
            import time as _time
            import math as _math
            now = _time.time()
            p2p = self._p2p
            # All nodes data aggregated
            # Difficulty window: time between block[max(0, height-2016)] and block[height]
            height = chain.height
            window_start = max(0, height - 2015)
            blk_curr  = chain.get_block_by_height(height)
            blk_start = chain.get_block_by_height(window_start)
            if blk_curr and blk_start and blk_curr.header.timestamp != blk_start.header.timestamp:
                actual_secs   = blk_curr.header.timestamp - blk_start.header.timestamp
                blocks_in_win = height - window_start
                avg_block_time = actual_secs / max(1, blocks_in_win)
            else:
                avg_block_time = 0

            # Blocks in last 24h
            cutoff_24h = now - 86400
            blocks_24h = 0
            txs_24h = 0
            for h in range(max(0, height - 2016), height + 1):
                b = chain.get_block_by_height(h)
                if b and b.header.timestamp >= cutoff_24h:
                    blocks_24h += 1
                    txs_24h += len(b.transactions)

            # Miner info
            # Get node hashrate - use same method as /mining/status endpoint
            node_hr = 0
            try:
                _m = getattr(self.server, "app_miner", None)
                if _m is None:
                    _m = getattr(self.server, "miner", None)
                if _m:
                    node_hr = float(getattr(_m, "_hashrate", 0) or getattr(_m, "hashrate_hps", 0) or 0)
            except Exception:
                pass

            ns = _get_network_stats(chain)
            total_hr = node_hr + ns["total_external_hashrate_hps"]

            # Target block time vs actual
            target_block_time = 600
            deficit_pct = round((avg_block_time - target_block_time) / target_block_time * 100, 1) if avg_block_time else 0

            # Next retarget
            next_retarget = 2016 - (height % 2016)
            blocks_to_halving = 210_000 - (height % 210_000)

            return {
                "height": height,
                "difficulty": chain.tip.header.difficulty if chain.tip else 1.0,
                "bits": hex(chain.tip.header.bits) if chain.tip else "0x1d00ffff",
                "target_block_time_s": target_block_time,
                "avg_block_time_s": round(avg_block_time, 1),
                "block_time_deviation_pct": deficit_pct,
                "next_retarget_blocks": next_retarget,
                "blocks_to_halving": blocks_to_halving,
                "blocks_24h": blocks_24h,
                "transactions_24h": txs_24h,
                "total_hashrate_hps": total_hr,
                "node_hashrate_hps": node_hr,
                "external_hashrate_hps": ns["total_external_hashrate_hps"],
                "active_external_miners": ns["active_external_miners"],
                "banned_miners": ns["banned_ips"],
                "supply_vito": chain.utxo.total_supply / 100_000_000 if hasattr(chain.utxo, "total_supply") else 550.0,
                "mempool_count": len(chain.mempool) if hasattr(chain, "mempool") else 0,
                "peers": p2p.peer_count if p2p else 0,
                "ts": int(now),
            }

        if parts == ["metrics"]:
            tip    = chain.tip
            ps     = chain.propagation_stats()
            lines  = [
                "# HELP vitocoin_height Current chain height",
                "# TYPE vitocoin_height gauge",
                f"vitocoin_height {chain.height}",
                "# HELP vitocoin_mempool_count Pending transaction count",
                "# TYPE vitocoin_mempool_count gauge",
                f"vitocoin_mempool_count {len(chain.mempool)}",
                "# HELP vitocoin_utxo_count UTXO set size",
                "# TYPE vitocoin_utxo_count gauge",
                f"vitocoin_utxo_count {chain.utxo.count}",
                "# HELP vitocoin_chain_work Accumulated chain PoW",
                "# TYPE vitocoin_chain_work counter",
                f"vitocoin_chain_work {chain.chain_work}",
                "# HELP vitocoin_uptime_seconds Node uptime",
                "# TYPE vitocoin_uptime_seconds counter",
                f"vitocoin_uptime_seconds {int(time.time() - self._start_time)}",
                "# HELP vitocoin_peers Connected peer count",
                "# TYPE vitocoin_peers gauge",
                f"vitocoin_peers {p2p.peer_count if p2p else 0}",
                "# HELP vitocoin_block_propagation_avg_ms Average block accept time (ms)",
                "# TYPE vitocoin_block_propagation_avg_ms gauge",
                f"vitocoin_block_propagation_avg_ms {ps['block_prop_avg_ms']}",
                "# HELP vitocoin_block_propagation_p99_ms P99 block accept time (ms)",
                "# TYPE vitocoin_block_propagation_p99_ms gauge",
                f"vitocoin_block_propagation_p99_ms {ps['block_prop_p99_ms']}",
                "# HELP vitocoin_tx_propagation_avg_ms Average tx accept time (ms)",
                "# TYPE vitocoin_tx_propagation_avg_ms gauge",
                f"vitocoin_tx_propagation_avg_ms {ps['tx_prop_avg_ms']}",
                "# HELP vitocoin_orphan_blocks_total Total orphan blocks received",
                "# TYPE vitocoin_orphan_blocks_total counter",
                f"vitocoin_orphan_blocks_total {ps['orphan_count']}",
                "# HELP vitocoin_reorg_total Total chain reorganizations",
                "# TYPE vitocoin_reorg_total counter",
                f"vitocoin_reorg_total {ps['reorg_count']}",
            ]
            payload = "\n".join(lines).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self._cors_headers()
            self.end_headers()
            self.wfile.write(payload)
            return True   # signal: already responded

        # ── /status ──────────────────────────────────────────────────
        if parts == ["status"]:
            s = chain.summary()
            s["peers"]      = p2p.peer_count if p2p else 0
            s["miner"]      = miner.stats if miner else None
            s["node_time"]  = int(time.time())
            s["uptime_s"]   = int(time.time() - self._start_time)
            return s

        # ── /peers ───────────────────────────────────────────────────
        if parts == ["peers"]:
            return {
                "count":       p2p.peer_count if p2p else 0,
                "outbound":    p2p.outbound_count if p2p else 0,
                "inbound":     p2p.inbound_count if p2p else 0,
                "peers":       p2p.peer_list() if p2p else [],
                "known_addrs": len(p2p.known_addrs) if p2p else 0,
            }

        # ── /blocks ──────────────────────────────────────────────────
        if parts == ["blocks"]:
            limit  = _int_param(qs, "limit",  20, 1, 100)
            offset = _int_param(qs, "offset",  0, 0, 10_000_000)
            total  = len(chain.chain)
            start  = max(0, total - offset - limit)
            end    = max(0, total - offset)
            blocks = chain.chain[start:end]
            return {
                "total":   total,
                "limit":   limit,
                "offset":  offset,
                "blocks": [b.to_dict(include_txs=False) for b in reversed(blocks)],
            }

        # ── /block/<id> ──────────────────────────────────────────────
        if len(parts) == 2 and parts[0] == "block":
            identifier = parts[1]
            if identifier.isdigit():
                h = int(identifier)
                if h < 0:
                    raise ValueError("Block height cannot be negative")
                block = chain.get_block_by_height(h)
            else:
                _require_hex64(identifier, "block hash")
                block = chain.get_block_by_hash(identifier.lower())
            if not block:
                return None
            include_txs = qs.get("txs", ["1"])[0] != "0"
            return block.to_dict(include_txs=include_txs)

        # ── /tx/<txid> ───────────────────────────────────────────────
        if len(parts) == 2 and parts[0] == "tx":
            txid = _require_hex64(parts[1], "txid")
            tx   = chain.get_tx(txid)
            return tx.to_dict() if tx else None

        # ── /balance/<addr>  (JS wallet-core.js alias) ───────────────
        if len(parts) == 2 and parts[0] == "balance":
            addr    = _require_address(parts[1], "address")
            balance = chain.utxo.balance(addr)
            utxos   = chain.utxo.utxos_for_address(addr)
            return {
                "address":         addr,
                "balance_satoshi": balance,
                "balance_vito":    balance / COIN,
                "utxo_count":      len(utxos),
            }

        # ── /utxos/<addr>  (JS transaction-builder.js alias) ─────────
        if len(parts) == 2 and parts[0] == "utxos":
            addr  = _require_address(parts[1], "address")
            utxos = chain.utxo.utxos_for_address(addr)
            return [
                {
                    "txid":   txid,
                    "index":  idx,
                    "value":  out.value,
                    "script_pubkey": out.script_pubkey.hex()
                                     if isinstance(out.script_pubkey, bytes)
                                     else out.script_pubkey,
                    "address": addr,
                }
                for txid, idx, out in utxos
            ]

        # ── /address/<addr> ──────────────────────────────────────────
        if len(parts) == 2 and parts[0] == "address":
            addr    = _require_address(parts[1], "address")
            balance = chain.utxo.balance(addr)
            utxos   = chain.utxo.utxos_for_address(addr)
            total   = len(utxos)
            limit   = _int_param(qs, "limit",  200, 1,     1000)
            offset  = _int_param(qs, "offset",   0, 0, 10_000_000)
            page    = utxos[offset : offset + limit]
            return {
                "address":          addr,
                "balance_satoshi":  balance,
                "balance_vito":     balance / COIN,
                "utxo_count":       total,
                "total":            total,
                "limit":            limit,
                "offset":           offset,
                "utxos": [
                    {"txid": txid, "index": idx,
                     "value": out.value, "value_vito": out.value / COIN}
                    for txid, idx, out in page
                ],
            }

        # ── /utxo/<txid>/<index> ──────────────────────────────────────
        if len(parts) == 3 and parts[0] == "utxo":
            txid = _require_hex64(parts[1], "txid")
            try:
                idx = int(parts[2])
            except ValueError:
                raise ValueError("UTXO index must be an integer")
            if idx < 0:
                raise ValueError("UTXO index cannot be negative")
            out = chain.utxo.get(txid, idx)
            if out is None:
                return None
            return {
                "txid":          txid,
                "index":         idx,
                "value":         out.value,
                "value_vito":    out.value / COIN,
                "script_pubkey": out.script_pubkey.hex()
                                 if isinstance(out.script_pubkey, bytes)
                                 else out.script_pubkey,
            }

        # ── /mempool ─────────────────────────────────────────────────
        if parts == ["mempool"]:
            limit = _int_param(qs, "limit", 100, 1, 500)
            return {
                "count": len(chain.mempool),
                "transactions": chain.mempool.to_dict_list(limit=limit),
            }

        # ── /mempool/stats ────────────────────────────────────────────
        if parts == ["mempool", "stats"]:
            mp      = chain.mempool
            txids   = list(mp._txs.keys())
            count   = len(txids)
            total_bytes = sum(mp._txs[t].size for t in txids)
            fee_rates = sorted(
                mp._fees[t] / max(mp._txs[t].size, 1)
                for t in txids
            ) if count else []

            def _pct(rates, p):
                if not rates:
                    return 0.0
                k = (len(rates) - 1) * p / 100
                lo, hi = int(k), min(int(k) + 1, len(rates) - 1)
                return round(rates[lo] + (rates[hi] - rates[lo]) * (k - lo), 4)

            return {
                "count":        count,
                "total_bytes":  total_bytes,
                "total_fees_satoshi": sum(mp._fees[t] for t in txids),
                "fee_rate_p25": _pct(fee_rates, 25),
                "fee_rate_p50": _pct(fee_rates, 50),
                "fee_rate_p75": _pct(fee_rates, 75),
                "fee_rate_min": round(fee_rates[0],  4) if fee_rates else 0.0,
                "fee_rate_max": round(fee_rates[-1], 4) if fee_rates else 0.0,
                "unit":         "sat/byte",
            }

        if len(parts) == 2 and parts[0] == "mempool":
            txid = _require_hex64(parts[1], "txid")
            tx   = chain.mempool._txs.get(txid)
            return tx.to_dict() if tx else None

        # ── /fee-estimate ─────────────────────────────────────────────
        if parts == ["fee-estimate"]:
            mp    = chain.mempool
            txids = list(mp._txs.keys())
            fee_rates = sorted(
                mp._fees[t] / max(mp._txs[t].size, 1)
                for t in txids
            ) if txids else []

            def _pct(rates, p):
                if not rates:
                    return 1.0   # minimum fallback: 1 sat/byte
                k = (len(rates) - 1) * p / 100
                lo, hi = int(k), min(int(k) + 1, len(rates) - 1)
                return round(rates[lo] + (rates[hi] - rates[lo]) * (k - lo), 4)

            return {
                "slow":          _pct(fee_rates, 25),
                "standard":      _pct(fee_rates, 50),
                "fast":          _pct(fee_rates, 75),
                "unit":          "sat/byte",
                "mempool_count": len(txids),
            }

        # ── /mining/template ─────────────────────────────────────────
        # Accepts optional ?wallet=<addr> so browser miner can get a template
        # even when the node is not running its own miner thread.
        if parts == ["mining", "template"]:
            # Register external miner
            _ip = _get_client_ip(self)
            if not _rate_limit(self, "GET"):
                self._json_error("rate limit exceeded", 429)
                return
            _wallet_param = qs.get("address", [""])[0] or qs.get("wallet", [""])[0]
            _hr_param = 0
            try: _hr_param = float(qs.get("hashrate", ["0"])[0])
            except: pass
            if _wallet_param:
                _register_miner(_ip, _wallet_param, _hr_param)

            from vitocoin.transaction import Transaction as _Tx
            from vitocoin.blockchain import Block as _Blk, block_subsidy as _sub
            wallet_addr = qs.get("wallet", [None])[0]
            if wallet_addr:
                _require_address(wallet_addr, "wallet")
            elif miner:
                wallet_addr = miner.wallet
            else:
                raise ValueError("Pass ?wallet=<V_address> or start node with --mine --wallet")
            tpl = getblocktemplate(chain, wallet_addr)
            # Add coinbase tx + computed merkle root for browser miner
            tip    = chain.tip
            height = (tip.height + 1) if tip else 1
            subsidy = _sub(height)
            coinbase = _Tx.coinbase(wallet_addr, height, subsidy)
            all_txids = [coinbase.txid] + [t["txid"] for t in tpl.get("transactions", [])]
            merkle_root = _Blk.compute_merkle_root(all_txids)
            tpl["coinbase_tx"]   = coinbase.to_dict()
            tpl["merkle_root"]   = merkle_root
            tpl["bits_int"]      = tpl.get("bits") if isinstance(tpl.get("bits"), int) else int(tpl.get("bits","1d00ffff"), 16)
            return tpl

        # ── /mining/status ───────────────────────────────────────────
        if parts == ["miners"]:
            import time as _time
            now = _time.time()
            result = []
            for ip, m in sorted(_MINER_REGISTRY.items(), key=lambda x: -x[1].get("hashrate_hps", 0)):
                if now - m["last_seen"] > 3600:
                    continue  # skip inactive (> 1h)
                result.append({
                    "ip_masked": ".".join(ip.split(".")[:2]) + ".x.x",  # privacy mask
                    "wallet": m["wallet"][:10] + "..." + m["wallet"][-6:] if len(m.get("wallet","")) > 16 else m.get("wallet",""),
                    "hashrate_str": f'{m.get("hashrate_hps",0)/1000:.1f} KH/s',
                    "hashrate_hps": m.get("hashrate_hps", 0),
                    "blocks_found": m.get("blocks", 0),
                    "shares": m.get("shares", 0),
                    "active_since": int(m.get("first_seen", now)),
                    "last_seen": int(m.get("last_seen", now)),
                })
            return {"count": len(result), "miners": result}

        if parts == ["mining", "status"]:
            return miner.stats if miner else {"mining": False}

        # ── /supply ──────────────────────────────────────────────────
        if parts == ["supply"]:
            return {
                "circulating_satoshi":  chain.utxo.total_supply,
                "circulating_vito":     chain.utxo.total_supply / COIN,
                "max_supply_vito":      21_000_000,
                "current_subsidy_vito": block_subsidy(chain.height) / COIN,
                "next_halving_blocks":  210_000 - (chain.height % 210_000),
            }

        # ── /market ──────────────────────────────────────────────────
        if parts == ["market"] or parts == ["market", "price"] or parts == ["market", "volume"]:
            import time as _t
            circ_vito = chain.utxo.total_supply / COIN
            PRICE_USD  = 0.0100
            ts = int(_t.time())
            if parts == ["market", "price"]:
                return {"price_usd": PRICE_USD, "symbol": "VITO", "ts": ts}
            if parts == ["market", "volume"]:
                return {"volume_24h_usd": 0, "note": "DEX integration pending — Phase 2", "ts": ts}
            return {
                "price_usd":          PRICE_USD,
                "price_source":       "fixed_initial_rate",
                "circulating_supply": circ_vito,
                "max_supply":         21_000_000,
                "market_cap_usd":     round(circ_vito * PRICE_USD, 4),
                "volume_24h_usd":     0,
                "volume_note":        "DEX integration pending (Phase 2)",
                "block_reward":       block_subsidy(chain.height) / COIN,
                "next_halving_blocks":210_000 - (chain.height % 210_000),
                "last_block":         chain.height,
                "best_hash":          chain.tip.hash if chain.chain else "",
                "network":            "mainnet",
                "ts":                 ts,
            }

        # ── /v1/merchants/status/<address> ────────────────────────────
        if parts[:2] == ["v1", "merchants"] and len(parts) >= 3 and parts[2] == "status":
            if not _WEBHOOKS_AVAILABLE:
                return {"error": "Webhook module not available"}
            addr = parts[3] if len(parts) > 3 else ""
            if not addr:
                raise ValueError("Address required: /v1/merchants/status/<address>")
            return {
                "address": addr,
                "subscriptions": list_subscriptions(addr),
                "payments": get_payment_history(addr),
            }

        # ── /merchant routes ─────────────────────────────────────────
        merchant = self._merchant
        if parts and parts[0] == "merchant":
            if not merchant:
                raise ValueError("Merchant API not enabled on this node")
            return self._route_merchant_get(parts[1:], qs, merchant)

        return None

    def _route_merchant_get(self, parts: list, qs: dict,
                            merchant: MerchantEngine) -> Optional[Any]:
        """Merchant-specific GET routes."""

        # GET /merchant/payment/<id>
        if len(parts) == 2 and parts[0] == "payment":
            pid     = parts[1]
            if len(pid) != 32 or not all(c in "0123456789abcdef" for c in pid):
                raise ValueError("Invalid payment_id format")
            payment = merchant.get_payment(pid)
            if payment is None:
                return None
            return payment.to_dict()

        # GET /merchant/verify/<id>
        if len(parts) == 2 and parts[0] == "verify":
            pid = parts[1]
            if len(pid) != 32 or not all(c in "0123456789abcdef" for c in pid):
                raise ValueError("Invalid payment_id format")
            is_paid, status, details = merchant.verify_payment(pid)
            return {"paid": is_paid, "status": status, **details}

        # GET /merchant/payments  (requires merchant_id query param)
        if len(parts) == 1 and parts[0] == "payments":
            mid    = qs.get("merchant_id", [None])[0]
            if not mid:
                raise ValueError("merchant_id query parameter required")
            status = qs.get("status", [None])[0]
            limit  = _int_param(qs, "limit",  50,  1, 200)
            offset = _int_param(qs, "offset",  0,  0, 10_000_000)
            items  = merchant.list_payments(mid, status=status, limit=limit, offset=offset)
            return {
                "merchant_id": mid,
                "count":       len(items),
                "payments":    [p.to_dict() for p in items],
            }

        # GET /merchant/stats
        if len(parts) == 1 and parts[0] == "stats":
            mid = qs.get("merchant_id", [None])[0]
            return merchant.stats(mid)

        return None

    # ── POST ───────────────────────────────────────────────────────────

    def do_POST(self):
        client_ip = self.client_address[0]
        # POST /tx uses strict tx bucket; /peers/connect uses admin bucket
        path_parts = [p for p in self.path.strip("/").split("/") if p]
        if path_parts and path_parts[0] == "tx":
            bucket = "tx"
        elif path_parts[:2] == ["peers", "connect"]:
            bucket = "admin"
            if not self._check_auth(required=True):
                return self._error(401, "Authentication required for peer management")
        elif path_parts and path_parts[0] == "merchant":
            bucket = "tx"
        else:
            bucket = "read"
        if not self._rate_limiter.check(client_ip, bucket):
            return self._error(429, "Rate limit exceeded — try again in 60 seconds")

        length = int(self.headers.get("Content-Length", 0))
        if length > self.MAX_BODY:
            return self._error(413, "Request body too large (max 1 MB)")

        raw   = self.rfile.read(length) if length else b""
        parts = [p for p in self.path.strip("/").split("/") if p]

        try:
            data = json.loads(raw) if raw else {}
        except json.JSONDecodeError as e:
            return self._error(400, f"Invalid JSON: {e}")

        try:
            body = self._route_post(parts, data)
            if body is None:
                return self._error(404, "Endpoint not found")
            self._ok(body)
        except ValueError as e:
            self._error(400, str(e))
        except Exception as e:
            log.error("API POST error on %s: %s", self.path, e, exc_info=True)
            self._error(500, "Internal server error")

    def _route_post(self, parts: list, data: dict) -> Optional[Any]:
        chain = self._chain
        p2p   = self._p2p

        # ── CSRF guard: only accept /tx posts from our frontend (F-06) ──
        if parts in (["tx"], ["tx", "broadcast"]):
            _allowed_origins = {
                'https://vitocoin.com',
                'http://localhost',
                'http://127.0.0.1',
            }
            _origin  = self.headers.get('Origin', '')
            _referer = self.headers.get('Referer', '')
            _origin_ok = (
                not _origin
                or _origin in _allowed_origins
                or any(_referer.startswith(o) for o in _allowed_origins)
            )
            if not _origin_ok:
                return self._error(403, 'Forbidden')

        # ── POST /tx  (also accepts /tx/broadcast as alias) ──────────
        if parts in (["tx"], ["tx", "broadcast"]):
            if not isinstance(data, dict):
                raise ValueError("Request body must be a JSON object")
            if "inputs" not in data or "outputs" not in data:
                raise ValueError("Transaction must have 'inputs' and 'outputs' fields")

            try:
                tx = Transaction.from_dict(data)
            except Exception as e:
                raise ValueError(f"Invalid transaction format: {e}")

            ok, reason = tx.validate_syntax()
            if not ok:
                return {"accepted": False, "txid": None, "error": reason}

            # Compute fee from UTXO set
            input_val = 0
            for inp in tx.inputs:
                utxo_out = chain.utxo.get(inp.prev_txid, inp.prev_index)
                if utxo_out:
                    input_val += utxo_out.value
            output_val = sum(o.value for o in tx.outputs)
            fee = max(0, input_val - output_val)

            ok, reason = chain.mempool.add(tx, fee, chain.utxo, chain.height)
            if ok and p2p:
                relayed = p2p.broadcast_tx(tx)
                return {"accepted": True, "txid": tx.txid, "fee": fee, "relayed_to": relayed}
            if ok:
                return {"accepted": True, "txid": tx.txid, "fee": fee, "relayed_to": 0}
            return {"accepted": False, "txid": None, "error": reason}

        # ── POST /block  (browser / external miner submission) ───────
        # Accepts a mined block as JSON: {header:{...}, transactions:[...], height:N}
        if parts == ["block"] or parts == ["mining", "submit"]:
            if not isinstance(data, dict):
                raise ValueError("Request body must be a JSON object")
            try:
                block = Block.from_dict(data)
            except Exception as e:
                raise ValueError(f"Invalid block format: {e}")
            ok, reason = chain.add_block(block)
            if ok and p2p:
                try:
                    p2p.broadcast_block(block)
                except Exception:
                    pass
            return {
                "accepted":    ok,
                "reason":      reason,
                "hash":        block.hash if ok else None,
                "height":      block.height if ok else None,
            }

        # ── POST /peers/connect ───────────────────────────────────────
        if parts == ["peers", "connect"]:
            if not isinstance(data, dict):
                raise ValueError("Request body must be a JSON object")
            host = data.get("host", "").strip()
            host = _validate_peer_host(host)   # raises ValueError on private IP / bad format
            try:
                port = int(data.get("port", 6333))
            except (TypeError, ValueError):
                raise ValueError("'port' must be an integer")
            if not (1 <= port <= 65535):
                raise ValueError("'port' must be between 1 and 65535")
            if not p2p:
                raise ValueError("P2P not running on this node")
            ok = p2p.connect(host, port)
            return {"connected": ok, "peer": f"{host}:{port}"}

        # ── POST /v1/merchants/register ───────────────────────────────
        if parts == ["v1", "merchants", "register"]:
            if not _WEBHOOKS_AVAILABLE:
                return {"error": "Webhook module not available"}
            if not isinstance(data, dict):
                raise ValueError("Request body must be a JSON object")
            address = str(data.get("address", "")).strip()
            url     = str(data.get("url", "")).strip()
            secret  = data.get("secret") or None
            if not address or not address.startswith("V"):
                raise ValueError("'address' must be a valid VitoCoin address")
            if not url or not (url.startswith("http://") or url.startswith("https://")):
                raise ValueError("'url' must be a valid http/https URL")
            return register_subscription(address, url, secret)

        # ── POST /merchant routes ─────────────────────────────────────
        if parts and parts[0] == "merchant":
            merchant = self._merchant
            if not merchant:
                raise ValueError("Merchant API not enabled on this node")
            return self._route_merchant_post(parts[1:], data, merchant)

        return None

    def _route_merchant_post(self, parts: list, data: dict,
                             merchant: MerchantEngine) -> Optional[Any]:
        """Merchant-specific POST routes."""

        # POST /merchant/create-payment
        if parts == ["create-payment"]:
            if not isinstance(data, dict):
                raise ValueError("Request body must be a JSON object")

            mid = data.get("merchant_id", "")
            if not mid or not isinstance(mid, str):
                raise ValueError("'merchant_id' is required")

            amount_raw = data.get("amount_satoshi")
            if amount_raw is None:
                # Accept amount_vito as alternative
                amount_vito = data.get("amount_vito")
                if amount_vito is None:
                    raise ValueError("'amount_satoshi' or 'amount_vito' is required")
                try:
                    amount_satoshi = int(float(amount_vito) * COIN)
                except (TypeError, ValueError):
                    raise ValueError("'amount_vito' must be a number")
            else:
                try:
                    amount_satoshi = int(amount_raw)
                except (TypeError, ValueError):
                    raise ValueError("'amount_satoshi' must be an integer")

            if amount_satoshi <= 0:
                raise ValueError("amount must be positive")

            description = str(data.get("description", ""))[:256]   # cap length
            webhook_url = str(data.get("webhook_url", ""))
            ttl_raw     = data.get("ttl_seconds")
            try:
                ttl = int(ttl_raw) if ttl_raw is not None else 900
                if not (60 <= ttl <= 86400):
                    raise ValueError("ttl_seconds must be 60–86400")
            except (TypeError, ValueError) as e:
                raise ValueError(f"'ttl_seconds': {e}")

            # Validate webhook URL format (basic — must be http/https if provided)
            if webhook_url and not (webhook_url.startswith("http://") or
                                    webhook_url.startswith("https://")):
                raise ValueError("'webhook_url' must be an http/https URL")

            metadata = data.get("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}

            payment = merchant.create_payment(
                merchant_id    = mid,
                amount_satoshi = amount_satoshi,
                description    = description,
                webhook_url    = webhook_url,
                ttl            = ttl,
                metadata       = metadata,
            )
            return payment.to_dict()

        return None

    # ── Response helpers ───────────────────────────────────────────────


    def _handle_sse(self):
        """Server-Sent Events endpoint — pushes real-time data to browser."""
        import time as _time
        chain  = self._chain
        miner  = self._miner
        p2p    = self._p2p

        self.send_response(200)
        self.send_header("Content-Type",      "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control",     "no-cache")
        self.send_header("Connection",        "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self._cors_headers()
        self.end_headers()

        last_height = -1
        last_mempool = -1
        try:
            while True:
                try:
                    s = chain.summary()
                    height   = s.get("height", 0)
                    mempool  = chain.mempool.count() if hasattr(chain.mempool, "count") else len(chain.mempool.txs) if hasattr(chain.mempool, "txs") else 0
                    ms       = miner.stats if miner else {}
                    peers    = p2p.peer_count if p2p else 0

                    # Build event payload
                    import json as _json
                    payload = _json.dumps({
                        "height":      height,
                        "best_hash":   s.get("best_hash", ""),
                        "difficulty":  s.get("difficulty", 1.0),
                        "peers":       peers,
                        "mempool":     mempool,
                        "supply_vito": s.get("supply_vito", 0),
                        "block_reward":s.get("block_reward", 50),
                        "next_halving":s.get("next_halving_blocks", 0),
                        "miner": {
                            "mining":      ms.get("mining", False),
                            "hashrate":    ms.get("hashrate_str", "0 H/s"),
                            "hashrate_hps":ms.get("hashrate_hps", 0),
                            "blocks_found":ms.get("blocks_found", 0),
                        },
                        "ts": int(_time.time()),
                    }, separators=(",", ":"))

                    event_type = "block" if height != last_height else ("mempool" if mempool != last_mempool else "ping")
                    last_height  = height
                    last_mempool = mempool

                    data = f"event: {event_type}\ndata: {payload}\n\n".encode("utf-8")
                    self.wfile.write(data)
                    self.wfile.flush()
                except BrokenPipeError:
                    break
                except Exception:
                    pass
                _time.sleep(1)
        except Exception:
            pass

    def _ok(self, body: Any):
        # If _route_get already wrote the response (e.g. /metrics), skip
        if body is True:
            return
        payload = json.dumps(body, indent=2, default=str).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type",   "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-VitoCoin-Version", VERSION)
        self._cors_headers()
        self._security_headers()
        self.end_headers()
        self.wfile.write(payload)

    def _error(self, code: int, message: str):
        payload = json.dumps({"error": message, "code": code},
                             separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type",   "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self._cors_headers()
        self.end_headers()
        self.wfile.write(payload)


# ═══════════════════════════════════════════════════════════════════════
#  SERVER
# ═══════════════════════════════════════════════════════════════════════

class VitoCoinHTTPServer(HTTPServer):
    """
    HTTPServer subclass that carries app state as instance attributes.
    This eliminates the class-level shared state of the original design,
    making it safe to run multiple server instances in tests.
    """

    def __init__(self, server_address, handler_class,
                 blockchain: Blockchain,
                 miner:      Optional[Miner]          = None,
                 p2p:        Optional[P2PNode]         = None,
                 api_keys:   Optional[Set[str]]        = None,
                 merchant:   Optional[MerchantEngine]  = None):
        super().__init__(server_address, handler_class)
        self.app_blockchain   = blockchain
        self.app_miner        = miner
        self.app_p2p          = p2p
        self.app_start_time   = time.time()
        self.app_rate_limiter = RateLimiter()
        self.app_api_keys     = api_keys or set()
        self.app_merchant     = merchant
        self.app_webhook_mgr  = None   # set by caller after construction
        # Serve the wallet/ static files from alongside node.py
        _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.app_static_dir = os.path.join(_root, "wallet")


def generate_api_key() -> str:
    """Generate a cryptographically secure API key (hex, 32 bytes = 64 chars)."""
    return secrets.token_hex(32)


def run_api(host: str = "0.0.0.0", port: int = 8000,
            blockchain: Blockchain = None,
            miner:      Miner      = None,
            p2p:        P2PNode    = None,
            api_keys:   Optional[Set[str]]       = None,
            merchant:   Optional[MerchantEngine] = None) -> VitoCoinHTTPServer:
    """
    Create and return the API server (not started yet).
    Caller is responsible for calling server.serve_forever() in a thread.

    api_keys: set of valid Bearer tokens. If empty/None, auth is disabled (open mode).
    merchant: MerchantEngine instance to enable merchant payment API endpoints.
    """
    if blockchain is None:
        raise ValueError("run_api requires a Blockchain instance")
    server = VitoCoinHTTPServer(
        (host, port), VitoCoinAPI,
        blockchain=blockchain, miner=miner, p2p=p2p, api_keys=api_keys,
        merchant=merchant,
    )
    log.info("🌍  API listening on http://%s:%d", host, port)
    if api_keys:
        log.info("🔑  API key authentication enabled (%d key(s))", len(api_keys))
    else:
        log.warning("⚠️  API running in open mode — no authentication configured")
    return server
