"""
VitoCoin P2P Network Protocol
============================================================
Full decentralized peer-to-peer network with:

  • TCP persistent connections with length-prefixed message framing
  • Network magic bytes to prevent cross-network pollution
  • Version handshake (like Bitcoin's version/verack)
  • Headers-first block sync (getheaders/headers/getdata/block)
  • Full block sync fallback via getblocks
  • Transaction relay with global seen_inv deduplication (no relay loops)
  • Peer discovery via addr/getaddr messages
  • Hardcoded seed node bootstrap
  • Peer ban scoring (DoS/spam protection)
  • Connection slot management (max inbound / max outbound)
  • Ping/pong with latency tracking
  • Message size limits

Phase 3 hardening:
  - Fixed verack: send("verack", b"") not send(b"verack")
  - Global seen_txids + seen_block_hashes prevent relay loops
  - _on_tx fee calculation fixed (proper UTXO lookup)
  - _on_getheaders added (batch headers-first sync reply)
  - validate-before-relay in _on_block
  - Seed node bootstrap on start()
  - stats() method for /metrics API
"""

import collections
import json
import logging
import os
import random
import socket
import struct
import threading
import time
from typing import Dict, List, Optional, Set, Tuple

from vitocoin.blockchain import Blockchain, Block, BlockHeader, VERSION, PROTOCOL_VERSION
from vitocoin.transaction import Transaction

log = logging.getLogger("VitoCoin.p2p")

# ── Protocol Constants ─────────────────────────────────────────────────
MAGIC              = b"\x56\x49\x54\x4F"   # "VITO" mainnet
MAX_MESSAGE_SIZE   = 32 * 1024 * 1024       # 32 MB
HEADER_SIZE        = 24                     # magic(4) + command(12) + length(4) + checksum(4)
MAX_PEERS          = 125                    # Max total connections
MAX_OUTBOUND       = 8                      # Max outbound connections
MAX_INBOUND        = 117                    # Max inbound connections
MAX_ADDR_PER_MSG   = 1000
BAN_THRESHOLD      = 100                    # Ban score threshold
BAN_DURATION       = 24 * 3600             # 24 hours
HANDSHAKE_TIMEOUT  = 10.0
PING_INTERVAL      = 30.0
CONNECT_TIMEOUT    = 10.0
PONG_TIMEOUT       = 90.0   # kick peer if no pong within this many seconds
HEADERS_PER_MSG    = 2000                  # batch size for getheaders reply
SEEN_INV_MAX       = 50_000               # evict oldest when seen set exceeds this

# Hardcoded seed nodes — add real IPs/hostnames at launch
SEED_NODES: List[Tuple[str, int]] = [
    ("213.139.77.18", 6334),
    ("84.201.20.90",  6334),
    # ("seed1.vitocoin.net", 6333),
]


# ═══════════════════════════════════════════════════════════════════════
#  MESSAGE CODEC
# ═══════════════════════════════════════════════════════════════════════

def _checksum(payload: bytes) -> bytes:
    from vitocoin.crypto import sha256d
    return sha256d(payload)[:4]

def encode_message(command: str, payload: bytes) -> bytes:
    """
    Bitcoin-style message framing:
    magic(4) | command(12, null-padded) | length(4) | checksum(4) | payload
    """
    cmd_bytes = command.encode("ascii").ljust(12, b"\x00")[:12]
    length    = struct.pack("<I", len(payload))
    chk       = _checksum(payload)
    return MAGIC + cmd_bytes + length + chk + payload

def decode_header(raw: bytes) -> Tuple[str, int, bytes]:
    """Returns (command, payload_length, checksum)."""
    if len(raw) < HEADER_SIZE:
        raise ValueError("Header too short")
    magic   = raw[:4]
    if magic != MAGIC:
        raise ValueError(f"Magic mismatch: {magic.hex()}")
    command = raw[4:16].rstrip(b"\x00").decode("ascii")
    length  = struct.unpack("<I", raw[16:20])[0]
    chk     = raw[20:24]
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message too large: {length}")
    return command, length, chk


# ═══════════════════════════════════════════════════════════════════════
#  PEER
# ═══════════════════════════════════════════════════════════════════════

class Peer:
    def __init__(self, sock: socket.socket, address: Tuple[str, int],
                 outbound: bool = False):
        self.sock         = sock
        self.host         = address[0]
        self.port         = address[1]
        self.outbound     = outbound
        self.version      = 0
        self.user_agent   = ""
        self.start_height = 0
        self.relay        = True
        self.handshake_done = False
        self.ban_score    = 0
        self.ping_nonce   = 0
        self.ping_sent    = 0.0
        self.latency_ms   = 0
        self.connected_at = time.time()
        self.bytes_sent   = 0
        self.bytes_recv   = 0
        self._lock        = threading.Lock()
        self.known_txids:  Set[str] = set()
        self.known_hashes: Set[str] = set()
        self.verack_sent   = False   # guard: send verack only once

    def send(self, command: str, payload: bytes = b"") -> bool:
        msg = encode_message(command, payload)
        try:
            with self._lock:
                self.sock.sendall(msg)
                self.bytes_sent += len(msg)
            return True
        except Exception:
            return False

    def send_json(self, command: str, data: dict) -> bool:
        return self.send(command, json.dumps(data, separators=(",", ":")).encode())

    def add_ban_score(self, score: int, reason: str = "") -> bool:
        """Returns True if peer should be banned."""
        self.ban_score += score
        if score > 0:
            log.debug(f"Peer {self} ban score +{score} ({reason}): total={self.ban_score}")
        return self.ban_score >= BAN_THRESHOLD

    def __repr__(self):
        return f"{self.host}:{self.port}"

    @property
    def id(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def uptime(self) -> float:
        return time.time() - self.connected_at


# ═══════════════════════════════════════════════════════════════════════
#  P2P NODE
# ═══════════════════════════════════════════════════════════════════════

class P2PNode:
    def __init__(self, blockchain: Blockchain, host: str = "0.0.0.0",
                 port: int = 6333, max_outbound: int = MAX_OUTBOUND,
                 seed_nodes: List[Tuple[str, int]] = None):
        self.chain        = blockchain
        self.host         = host
        self.port         = port
        self.max_outbound = max_outbound
        self._seed_nodes  = seed_nodes or list(SEED_NODES)
        # Deduplication: track IPs we have an outbound connection to
        self._outbound_ips: set = set()  # {host} strings

        self.peers:      Dict[str, Peer]  = {}
        self.banned:     Dict[str, float] = {}
        self.known_addrs: List[Tuple[str, int]] = []

        # Global deduplication — prevents relay loops across all peers
        # OrderedDict used for LRU eviction (insertion order preserved)
        self._seen_txids:        collections.OrderedDict = collections.OrderedDict()
        self._seen_block_hashes: collections.OrderedDict = collections.OrderedDict()
        self._seen_lock          = threading.Lock()

        self._lock        = threading.RLock()
        self._server: Optional[socket.socket] = None
        self._running     = False

    # ── Startup ────────────────────────────────────────────────────────

    def start(self):
        self._running = True
        self._server  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._server.bind((self.host, self.port))
        self._server.listen(64)
        self._server.settimeout(1.0)
        log.info("🌐  P2P listening on %s:%d", self.host, self.port)
        threading.Thread(target=self._accept_loop,  daemon=True, name="p2p-accept").start()
        threading.Thread(target=self._ping_loop,    daemon=True, name="p2p-ping").start()
        threading.Thread(target=self._addr_loop,    daemon=True, name="p2p-addr").start()
        threading.Thread(target=self._ban_cleanup,  daemon=True, name="p2p-ban-cleanup").start()
        if self._seed_nodes:
            threading.Thread(target=self._bootstrap,      daemon=True, name="p2p-bootstrap").start()
            threading.Thread(target=self._reconnect_loop, daemon=True, name="p2p-reconnect").start()

    def _bootstrap(self):
        """Connect to seed nodes after a short startup delay."""
        time.sleep(1.0)
        log.info("P2P bootstrap: trying %d seed node(s)", len(self._seed_nodes))
        for host, port in self._seed_nodes:
            if self.outbound_count >= self.max_outbound:
                break
            self.connect(host, port)
            time.sleep(0.5)

    def _reconnect_loop(self):
        """Continuously reconnect to seed nodes when peer count drops below expected."""
        time.sleep(10.0)  # wait for bootstrap to complete first
        while self._running:
            try:
                time.sleep(15)
                if not self._running:
                    break
                with self._lock:
                    current_peers = set(self.peers.keys())
                    current_outbound = self.outbound_count
                # Reconnect if any seed node is missing
                for host, port in self._seed_nodes:
                    key = f"{host}:{port}"
                    if key not in current_peers and host not in self.banned:
                        log.info("Reconnect loop: reconnecting to %s:%d (outbound=%d)",
                                 host, port, current_outbound)
                        try:
                            self.connect(host, port)
                            time.sleep(1.0)
                        except Exception as e:
                            log.debug("Reconnect to %s:%d failed: %s", host, port, e)
            except Exception as e:
                log.warning("Reconnect loop error: %s", e)

    def stop(self):
        self._running = False
        if self._server:
            try:
                self._server.close()
            except Exception:
                pass
        with self._lock:
            for peer in list(self.peers.values()):
                try:
                    peer.sock.close()
                except Exception:
                    pass

    # ── Outbound connections ───────────────────────────────────────────

    def connect(self, host: str, port: int) -> bool:
        if self._is_banned(host):
            log.debug(f"Skipping banned peer {host}")
            return False
        if self.outbound_count >= self.max_outbound:
            return False
        if f"{host}:{port}" in self.peers:
            return False
        try:
            sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            peer = Peer(sock, (host, port), outbound=True)
            with self._lock:
                self._outbound_ips.add(host)
            self._register_peer(peer)
            threading.Thread(target=self._peer_loop, args=(peer,),
                             daemon=True, name=f"peer-{host}:{port}").start()
            self._send_version(peer)
            return True
        except Exception as e:
            log.debug(f"Connect failed to {host}:{port}: {e}")
            return False

    def connect_many(self, addrs: List[Tuple[str, int]]) -> None:
        for host, port in addrs:
            if self.outbound_count < self.max_outbound:
                threading.Thread(target=self.connect, args=(host, port), daemon=True).start()
                time.sleep(0.1)

    # ── Broadcast ─────────────────────────────────────────────────────

    def broadcast_tx(self, tx: Transaction) -> int:
        """Relay transaction to peers that haven't seen it. Returns relay count."""
        # Global dedup: if we've already broadcast this tx, don't relay again
        with self._seen_lock:
            if tx.txid in self._seen_txids:
                return 0
            self._seen_txids[tx.txid] = True
            if len(self._seen_txids) > SEEN_INV_MAX:
                # LRU eviction: remove oldest 10% (first inserted)
                for _ in range(SEEN_INV_MAX // 10):
                    self._seen_txids.popitem(last=False)
        payload = json.dumps(tx.to_dict(), separators=(",", ":")).encode()
        count   = 0
        with self._lock:
            peers = list(self.peers.values())
        for peer in peers:
            if tx.txid not in peer.known_txids and peer.handshake_done:
                if peer.send("tx", payload):
                    peer.known_txids.add(tx.txid)
                    count += 1
        return count

    def broadcast_block(self, block: Block) -> int:
        """Announce new block to peers (headers first)."""
        # Global dedup: only relay a block hash once across the node lifetime
        with self._seen_lock:
            if block.hash in self._seen_block_hashes:
                return 0
            self._seen_block_hashes[block.hash] = True
            if len(self._seen_block_hashes) > SEEN_INV_MAX:
                # LRU eviction: remove oldest 10% (first inserted)
                for _ in range(SEEN_INV_MAX // 10):
                    self._seen_block_hashes.popitem(last=False)
        header_payload = json.dumps(block.header.to_dict(), separators=(",", ":")).encode()
        count = 0
        with self._lock:
            peers = list(self.peers.values())
        for peer in peers:
            if block.hash not in peer.known_hashes and peer.handshake_done:
                peer.send("headers", header_payload)
                peer.known_hashes.add(block.hash)
                count += 1
        return count

    def broadcast_inv(self, inv_type: str, hashes: List[str]) -> None:
        """Send inventory announcement (like Bitcoin's inv message)."""
        payload = json.dumps({"type": inv_type, "hashes": hashes}, separators=(",", ":")).encode()
        with self._lock:
            peers = list(self.peers.values())
        for peer in peers:
            if peer.handshake_done:
                peer.send("inv", payload)

    # ── Accept loop ────────────────────────────────────────────────────

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._server.accept()
                host = addr[0]
                if self._is_banned(host):
                    conn.close()
                    continue
                if self.inbound_count >= MAX_INBOUND:
                    conn.close()
                    continue
                peer = Peer(conn, addr, outbound=False)
                self._register_peer(peer)
                threading.Thread(target=self._peer_loop, args=(peer,),
                                daemon=True, name=f"peer-in-{host}").start()
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    log.error(f"Accept error: {e}")

    # ── Peer message loop ──────────────────────────────────────────────

    def _peer_loop(self, peer: Peer):
        try:
            peer.sock.settimeout(120.0)
            while self._running:
                command, payload = self._recv_message(peer)
                self._dispatch(command, payload, peer)
        except Exception as e:
            log.debug(f"Peer {peer} disconnected: {type(e).__name__}: {e}")
        finally:
            self._remove_peer(peer)

    def _recv_message(self, peer: Peer) -> Tuple[str, bytes]:
        header = self._recv_exact(peer.sock, HEADER_SIZE)
        command, length, expected_chk = decode_header(header)
        if length == 0:
            return command, b""
        payload = self._recv_exact(peer.sock, length)
        peer.bytes_recv += HEADER_SIZE + length
        # Verify checksum
        actual_chk = _checksum(payload)
        if actual_chk != expected_chk:
            peer.add_ban_score(20, "bad checksum")
            raise ValueError("Checksum mismatch")
        return command, payload

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionResetError("Connection closed")
            buf += chunk
        return buf

    # ── Message dispatcher ─────────────────────────────────────────────

    # Commands allowed before handshake completes (state-machine enforcement)
    _PRE_HANDSHAKE_CMDS = frozenset(["version", "verack", "reject"])

    def _dispatch(self, command: str, payload: bytes, peer: Peer):
        # State-machine: only allow pre-handshake commands until verack is received
        if not peer.handshake_done and command not in self._PRE_HANDSHAKE_CMDS:
            log.debug("Dropping '%s' from %s — handshake not complete", command, peer)
            peer.add_ban_score(5, f"message before handshake: {command}")
            return

        handlers = {
            "version":    self._on_version,
            "verack":     self._on_verack,
            "ping":       self._on_ping,
            "pong":       self._on_pong,
            "getaddr":    self._on_getaddr,
            "addr":       self._on_addr,
            "inv":        self._on_inv,
            "getdata":    self._on_getdata,
            "tx":         self._on_tx,
            "headers":    self._on_headers,
            "getheaders": self._on_getheaders,
            "getblocks":  self._on_getblocks,
            "block":      self._on_block,
            "mempool":    self._on_mempool,
            "reject":     self._on_reject,
        }
        handler = handlers.get(command)
        if handler:
            try:
                data = json.loads(payload) if payload else {}
                handler(data, peer)
            except Exception as e:
                log.debug(f"Error handling '{command}' from {peer}: {e}")
                peer.add_ban_score(1, f"handler error: {command}")
        else:
            log.debug(f"Unknown command '{command}' from {peer}")

    # ── Handshake ──────────────────────────────────────────────────────

    def _send_version(self, peer: Peer):
        peer.send_json("version", {
            "version":       PROTOCOL_VERSION,
            "user_agent":    f"/{VERSION}/",
            "start_height":  self.chain.height,
            "relay":         True,
            "timestamp":     int(time.time()),
            "nonce":         random.getrandbits(64),
            "addr_from":     {"host": self.host, "port": self.port},
        })

    def _on_version(self, data: dict, peer: Peer):
        if peer.handshake_done:
            peer.add_ban_score(1, "duplicate version")
            return

        # ── Tie-breaker: drop duplicate inbound when we are already dialling
        # outbound to the same host.  Higher IP keeps its outbound connection.
        if not peer.outbound and peer.host in self._outbound_ips:
            import socket as _sock
            try:
                # Use outbound socket IP to get real external address
                s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
                s.connect((peer.host, 1))
                local_ip = s.getsockname()[0]
                s.close()
            except Exception:
                local_ip = self.host if self.host != "0.0.0.0" else "0.0.0.0"
            if local_ip > peer.host:
                # We are the higher-IP node — keep our outbound, drop their inbound
                log.info(
                    "Dropped duplicate inbound connection from %s "
                    "(we have outbound; local=%s > remote=%s)",
                    peer, local_ip, peer.host
                )
                self._remove_peer(peer)
                return
            else:
                # Remote is higher — they will drop their inbound;
                # we drop our outbound duplicate
                for p in list(self.peers.values()):
                    if p.outbound and p.host == peer.host:
                        log.info(
                            "Dropped duplicate outbound to %s "
                            "(remote=%s > local=%s keeps outbound)",
                            peer.host, peer.host, local_ip
                        )
                        self._remove_peer(p)
                        break

        peer.version      = data.get("version", 0)
        peer.user_agent   = data.get("user_agent", "")
        peer.start_height = data.get("start_height", 0)
        peer.relay        = data.get("relay", True)
        # FIX: send("verack", b"") — not send(b"verack") which passes bytes as command
        if not peer.verack_sent:
            peer.send("verack", b"")
            peer.verack_sent = True
        if not peer.outbound:
            self._send_version(peer)
        log.info("🤝  Peer %s | agent=%s | height=%d",
                 peer, peer.user_agent, peer.start_height)
        # FIX: For outbound connections, verack may arrive before version.
        # If handshake is already done (verack received first), trigger sync now.
        if peer.handshake_done and peer.start_height > self.chain.height:
            log.info("📥  Triggering header sync with %s (their=%d, ours=%d)",
                     peer, peer.start_height, self.chain.height)
            self._request_headers(peer)

    def _on_verack(self, data: dict, peer: Peer):
        peer.handshake_done = True
        peer.send("getaddr", b"")
        if peer.start_height > self.chain.height:
            self._request_headers(peer)
        log.info("✅  Handshake complete with %s (their=%d, ours=%d)",
                 peer, peer.start_height, self.chain.height)
        # Schedule a delayed check in case version arrived after verack (race condition)
        import threading
        def _delayed_sync_check():
            import time; time.sleep(2)
            try:
                if peer.handshake_done and peer.start_height > self.chain.height:
                    log.info("📥  Delayed sync trigger for %s (their=%d, ours=%d)",
                             peer, peer.start_height, self.chain.height)
                    self._request_headers(peer)
            except Exception:
                pass
        threading.Thread(target=_delayed_sync_check, daemon=True).start()

    def _request_headers(self, peer: Peer):
        """Request missing headers via getheaders (headers-first sync)."""
        tip = self.chain.tip
        peer.send_json("getheaders", {
            "from_hash":   tip.hash if tip else "0" * 64,
            "from_height": self.chain.height,
            "count":       HEADERS_PER_MSG,
        })

    # ── Peer discovery ─────────────────────────────────────────────────

    def _on_getaddr(self, data: dict, peer: Peer):
        with self._lock:
            addrs = [{"host": p.host, "port": p.port}
                     for p in self.peers.values()
                     if p.handshake_done and p.id != peer.id]
        random.shuffle(addrs)
        peer.send_json("addr", {"addrs": addrs[:MAX_ADDR_PER_MSG]})

    def _on_addr(self, data: dict, peer: Peer):
        addrs = data.get("addrs", [])
        if len(addrs) > MAX_ADDR_PER_MSG:
            peer.add_ban_score(20, "too many addrs")
            return
        import ipaddress as _ipaddress
        new_addrs = []
        for a in addrs:
            host = str(a.get("host", "")).strip()
            if not host:
                continue
            # Validate port
            try:
                port = int(a.get("port", 6333))
                if not (1 <= port <= 65535):
                    continue
            except (TypeError, ValueError):
                continue
            # Skip private/loopback IPs — don't let peers inject RFC1918 entries
            try:
                addr_obj = _ipaddress.ip_address(host)
                if addr_obj.is_private or addr_obj.is_loopback or addr_obj.is_link_local:
                    continue
            except ValueError:
                low = host.lower()
                if low in ("localhost", "ip6-localhost", "ip6-loopback") or low.endswith(".local"):
                    continue
            if (host, port) not in self.known_addrs:
                self.known_addrs.append((host, port))
                new_addrs.append((host, port))
        # Cap known_addrs to prevent memory growth
        if len(self.known_addrs) > 10_000:
            self.known_addrs = self.known_addrs[-10_000:]
        # Try connecting to new peers
        if self.outbound_count < self.max_outbound:
            self.connect_many(new_addrs[:3])

    # ── Inventory ──────────────────────────────────────────────────────

    def _on_inv(self, data: dict, peer: Peer):
        inv_type = data.get("type")
        hashes   = data.get("hashes", [])
        want = []
        with self._seen_lock:
            seen_tx    = self._seen_txids
            seen_block = self._seen_block_hashes
        with self._lock:
            for h in hashes:
                if inv_type == "tx" and h not in self.chain.mempool and h not in seen_tx:
                    want.append(h)
                elif inv_type == "block" and h not in self.chain.by_hash and h not in seen_block:
                    want.append(h)
        if want:
            peer.send_json("getdata", {"type": inv_type, "hashes": want})

    def _on_getdata(self, data: dict, peer: Peer):
        inv_type = data.get("type")
        hashes   = data.get("hashes", [])
        for h in hashes[:50]:   # rate limit
            if inv_type == "tx":
                tx = self.chain.get_tx(h)
                if tx:
                    peer.send("tx", json.dumps(tx.to_dict()).encode())
            elif inv_type == "block":
                block = self.chain.get_block_by_hash(h)
                if block:
                    peer.send("block", json.dumps(block.to_dict()).encode())

    # ── Transactions ───────────────────────────────────────────────────

    def _on_tx(self, data: dict, peer: Peer):
        try:
            tx = Transaction.from_dict(data)
            # Mark as seen immediately so we don't relay back to sender
            with self._seen_lock:
                if tx.txid in self._seen_txids:
                    return   # Already processed; suppress duplicate
                self._seen_txids[tx.txid] = True
                if len(self._seen_txids) > SEEN_INV_MAX:
                    for _ in range(SEEN_INV_MAX // 10):
                        self._seen_txids.popitem(last=False)
            # Proper fee calculation via UTXO lookup
            input_val = 0
            for inp in tx.inputs:
                utxo_out = self.chain.utxo.get(inp.prev_txid, inp.prev_index)
                if utxo_out is not None:
                    input_val += utxo_out.value
            fee = max(0, input_val - sum(o.value for o in tx.outputs))
            ok, reason = self.chain.mempool.add(tx, fee, self.chain.utxo, self.chain.height)
            if ok:
                peer.known_txids.add(tx.txid)
                self.broadcast_tx(tx)
            else:
                log.debug(f"TX rejected from {peer}: {reason}")
                if "script" in reason.lower():
                    peer.add_ban_score(10, reason)
        except Exception as e:
            peer.add_ban_score(5, f"bad tx: {e}")

    # ── Blocks ─────────────────────────────────────────────────────────


    def _request_headers_if_behind(self, peer: "Peer"):
        """After accepting a block, request more headers if peer is ahead."""
        try:
            if peer.start_height > self.chain.height:
                self._request_headers(peer)
        except Exception:
            pass

    def resync_all_peers(self):
        """Force re-request headers from all peers that are ahead."""
        with self._lock:
            peers = list(self.peers.values())
        for peer in peers:
            if peer.handshake_done and peer.start_height > self.chain.height:
                try:
                    self._request_headers(peer)
                except Exception:
                    pass

    def _periodic_sync_loop(self):
        """Periodically re-request headers from peers that are ahead."""
        import time
        while self._running:
            time.sleep(10)
            try:
                with self._lock:
                    peers = list(self.peers.values())
                for peer in peers:
                    try:
                        if peer.handshake_done and peer.start_height > self.chain.height:
                            log.info("⏱  Periodic sync: requesting headers from %s (their=%d, ours=%d)",
                                     peer, peer.start_height, self.chain.height)
                            self._request_headers(peer)
                    except Exception:
                        pass
            except Exception:
                pass

    def _on_headers(self, data: dict, peer: Peer):
        """Headers-first: receive header, request full block if unknown."""
        from vitocoin.blockchain import BlockHeader
        try:
            header = BlockHeader.from_dict(data)
            h      = header.hash()
            if h not in self.chain.by_hash:
                peer.send_json("getdata", {"type": "block", "hashes": [h]})
        except Exception as e:
            peer.add_ban_score(5, f"bad header: {e}")

    def _on_getheaders(self, data: dict, peer: Peer):
        """Reply with a batch of headers starting after from_hash/from_height."""
        from_height = int(data.get("from_height", 0))
        count       = min(int(data.get("count", HEADERS_PER_MSG)), HEADERS_PER_MSG)
        start       = from_height + 1  # send headers *after* the peer's tip
        batch       = self.chain.chain[start:start + count]
        for blk in batch:
            peer.send_json("headers", blk.header.to_dict())

    def _on_getblocks(self, data: dict, peer: Peer):
        try:
            from_height = int(data.get("from_height", 0))
        except (TypeError, ValueError):
            peer.add_ban_score(5, "bad from_height in getblocks")
            return
        if from_height < 0:
            peer.add_ban_score(5, "negative from_height")
            return
        # Cap at 500 blocks per request to prevent DoS via bulk data transfer
        MAX_GETBLOCKS = 500
        blocks = self.chain.chain[from_height:from_height + MAX_GETBLOCKS]
        for b in blocks:
            peer.send("block", json.dumps(b.to_dict()).encode())

    def _on_block(self, data: dict, peer: Peer):
        try:
            block = Block.from_dict(data)
            # Mark seen before add_block so concurrent relays skip it
            with self._seen_lock:
                if block.hash in self._seen_block_hashes:
                    return
                self._seen_block_hashes[block.hash] = True
                if len(self._seen_block_hashes) > SEEN_INV_MAX:
                    for _ in range(SEEN_INV_MAX // 10):
                        self._seen_block_hashes.popitem(last=False)
            ok, reason = self.chain.add_block(block)
            if ok:
                peer.known_hashes.add(block.hash)
                # validate-before-relay: only broadcast on successful add
                self.broadcast_block(block)
                # Continue syncing if peer has more blocks
                self._request_headers_if_behind(peer)
            else:
                log.debug(f"Block rejected from {peer}: {reason}")
                if "PoW" in reason or "Merkle" in reason or "script" in reason:
                    peer.add_ban_score(20, reason)
        except Exception as e:
            peer.add_ban_score(10, f"bad block: {e}")

    # ── Other messages ─────────────────────────────────────────────────

    def _on_ping(self, data: dict, peer: Peer):
        peer.send_json("pong", {"nonce": data.get("nonce", 0)})

    def _on_pong(self, data: dict, peer: Peer):
        if data.get("nonce") == peer.ping_nonce and peer.ping_sent > 0:
            peer.latency_ms = int((time.time() - peer.ping_sent) * 1000)
            peer.ping_sent  = 0

    def _on_mempool(self, data: dict, peer: Peer):
        """Peer requested our mempool."""
        for tx in list(self.chain.mempool.values()):
            if tx.txid not in peer.known_txids:
                peer.send("tx", json.dumps(tx.to_dict()).encode())
                peer.known_txids.add(tx.txid)

    def _on_reject(self, data: dict, peer: Peer):
        log.debug(f"Peer {peer} rejected: {data}")

    # ── Background tasks ───────────────────────────────────────────────

    def _ping_loop(self):
        while self._running:
            time.sleep(PING_INTERVAL)
            with self._lock:
                peers = list(self.peers.values())
            now = time.time()
            for peer in peers:
                if not peer.handshake_done:
                    continue
                # Kick peers that haven't responded to a ping within PONG_TIMEOUT
                if peer.ping_sent > 0 and (now - peer.ping_sent) > PONG_TIMEOUT:
                    log.info("Peer %s pong timeout — disconnecting", peer)
                    try:
                        peer.sock.close()
                    except Exception:
                        pass
                    continue
                nonce = random.getrandbits(32)
                peer.ping_nonce = nonce
                peer.ping_sent  = time.time()
                peer.send_json("ping", {"nonce": nonce})

    def _addr_loop(self):
        """Periodically share our address list."""
        while self._running:
            time.sleep(300)
            with self._lock:
                peers = list(self.peers.values())
            for peer in peers:
                if peer.handshake_done:
                    self._on_getaddr({}, peer)

    def _ban_cleanup(self):
        """Periodically evict expired ban entries to prevent memory growth."""
        while self._running:
            time.sleep(3600)   # run every hour
            try:
                now = time.time()
                expired = [host for host, until in list(self.banned.items()) if now >= until]
                for host in expired:
                    self.banned.pop(host, None)
                if expired:
                    log.debug("Ban cleanup: removed %d expired ban(s)", len(expired))
            except Exception:
                pass

    # ── Ban management ─────────────────────────────────────────────────

    def _is_banned(self, host: str) -> bool:
        ban_until = self.banned.get(host, 0)
        if time.time() < ban_until:
            return True
        self.banned.pop(host, None)
        return False

    def ban_peer(self, peer: Peer) -> None:
        log.warning(f"🚫  Banning peer {peer} (score={peer.ban_score})")
        self.banned[peer.host] = time.time() + BAN_DURATION
        try:
            peer.sock.close()
        except Exception:
            pass

    # ── Peer registry ──────────────────────────────────────────────────

    def _register_peer(self, peer: Peer) -> None:
        with self._lock:
            self.peers[peer.id] = peer
            if (peer.host, peer.port) not in self.known_addrs:
                self.known_addrs.append((peer.host, peer.port))
        log.info(f"{'→' if peer.outbound else '←'}  Peer connected: {peer} ({len(self.peers)} total)")

    def _remove_peer(self, peer: Peer) -> None:
        with self._lock:
            self.peers.pop(peer.id, None)
            if peer.outbound:
                self._outbound_ips.discard(peer.host)
        try:
            peer.sock.close()
        except Exception:
            pass
        if peer.ban_score >= BAN_THRESHOLD:
            self.ban_peer(peer)
        log.info(f"✂️   Peer disconnected: {peer} ({len(self.peers)} remaining)")

    # ── Stats ──────────────────────────────────────────────────────────

    @property
    def peer_count(self) -> int:
        return len(self.peers)

    @property
    def outbound_count(self) -> int:
        return sum(1 for p in self.peers.values() if p.outbound)

    @property
    def inbound_count(self) -> int:
        return sum(1 for p in self.peers.values() if not p.outbound)

    def peer_list(self) -> List[dict]:
        with self._lock:
            return [{
                "id":         p.id,
                "outbound":   p.outbound,
                "version":    p.version,
                "user_agent": p.user_agent,
                "height":     p.start_height,
                "latency_ms": p.latency_ms,
                "ban_score":  p.ban_score,
                "uptime_s":   int(p.uptime),
            } for p in self.peers.values()]

    def stats(self) -> dict:
        """Return network statistics dict (used by /metrics API)."""
        with self._seen_lock:
            seen_tx    = len(self._seen_txids)
            seen_block = len(self._seen_block_hashes)
        total_sent = sum(p.bytes_sent for p in self.peers.values())
        total_recv = sum(p.bytes_recv for p in self.peers.values())
        return {
            "peers":            self.peer_count,
            "outbound":         self.outbound_count,
            "inbound":          self.inbound_count,
            "banned":           len(self.banned),
            "known_addrs":      len(self.known_addrs),
            "seen_txids":       seen_tx,
            "seen_block_hashes":seen_block,
            "bytes_sent":       total_sent,
            "bytes_recv":       total_recv,
        }
