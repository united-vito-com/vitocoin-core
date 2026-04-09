"""
VitoCoin Blockchain Engine
============================================================
Full Bitcoin-equivalent blockchain with upgrades:

  Bitcoin equivalents:
  • SHA-256d Proof-of-Work with real difficulty target (256-bit comparison)
  • Difficulty retargeting every 2,016 blocks (≈2 weeks at 1-min blocks)
  • Chain reorganization (longest chain / most work wins)
  • Block header serialization identical to Bitcoin's 80-byte header
  • BIP-34 block height in coinbase
  • Coinbase maturity (100 blocks)
  • Merkle tree for transaction integrity
  • Checkpoints for fast sync protection

  VitoCoin upgrades beyond Bitcoin:
  • 1-minute block time (10× faster than Bitcoin)
  • Transaction fee market with priority ordering
  • Compact block relay (headers-first sync)
  • Orphan block pool with reconnect logic
  • Per-block timestamp median-time-past (MTP) check
  • Block size: 4 MB (4× Bitcoin pre-SegWit)
  • Persistent chain state via LevelDB (SQLite fallback)
  • O(1) transaction index (txid → block_height + tx_index)
"""

import collections
import hashlib
import json
import os
import struct
import time
import threading
import logging
from typing import List, Optional, Dict, Tuple

from vitocoin.crypto import sha256d, sha256d_hex
from vitocoin.transaction import Transaction, TxInput, TxOutput, UTXOSet, Mempool, COIN
from vitocoin.store import (
    open_store, ChainStore,
    key_block_header, key_block_height, key_block_body,
    key_utxo, key_undo, key_tx_index, key_meta,
)

log = logging.getLogger("VitoCoin.chain")

# ── Network Parameters ─────────────────────────────────────────────────
COIN_PARAMS = {
    "mainnet": {
        "magic":           b"\x56\x49\x54\x4F",   # "VITO"
        "default_port":    6333,
        "genesis_hash":    None,  # computed at startup
        "dns_seeds":       [
            "seed1.vitocoin.net",
            "seed2.vitocoin.net",
            "seed.vitocoin.org",
        ],
        "checkpoints": {
            # height: expected_hash  (populated after genesis)
        },
    },
    "testnet": {
        "magic":           b"\x56\x49\x54\x54",   # "VITT"
        "default_port":    16333,
        "dns_seeds":       [],
        "checkpoints":     {},
    },
}

# ── Consensus Constants ────────────────────────────────────────────────
BLOCK_REWARD_INITIAL  = 50 * COIN
HALVING_INTERVAL      = 210_000
MAX_SUPPLY            = 21_000_000 * COIN
TARGET_BLOCK_TIME     = 600            # 600 seconds — Bitcoin-exact 10 min target
DIFFICULTY_WINDOW     = 2016           # Bitcoin-exact: retarget every 2,016 blocks (~2 weeks)
MAX_BLOCK_SIZE        = 4_000_000      # 4 MB (VitoCoin upgrade)
MAX_BLOCK_WEIGHT      = 16_000_000
MAX_ORPHANS           = 5_000          # Hard cap on orphan pool to prevent DoS
MAX_REORG_DEPTH       = 100            # Refuse reorgs deeper than this (DoS guard)
GENESIS_BITS          = 0x1d00ffff     # Minimum difficulty floor (~Bitcoin genesis) — prevents trivially easy blocks
GENESIS_TIMESTAMP     = 1_744_070_400  # Apr 2026 fresh start  # Nov 2023
GENESIS_NONCE         = 0
MEDIAN_TIME_PAST_N    = 11             # MTP uses median of last 11 blocks
MAX_FUTURE_BLOCK_TIME = 7200           # Max 2 hours ahead of network time
MIN_CHAIN_WORK_BITS   = 1             # Minimum required work to accept chain

VERSION               = "VitoCoin/2.0.0"
PROTOCOL_VERSION      = 70015


# ═══════════════════════════════════════════════════════════════════════
#  BLOCK HEADER
# ═══════════════════════════════════════════════════════════════════════

class BlockHeader:
    """
    80-byte block header — identical structure to Bitcoin.
    Fields: version(4) | prev_hash(32) | merkle_root(32) | time(4) | bits(4) | nonce(4)
    """
    SIZE = 80

    def __init__(self, version: int, prev_hash: str, merkle_root: str,
                 timestamp: int, bits: int, nonce: int):
        self.version     = version
        self.prev_hash   = prev_hash      # 64 hex chars (256 bits)
        self.merkle_root = merkle_root    # 64 hex chars
        self.timestamp   = timestamp      # Unix timestamp (int)
        self.bits        = bits           # Compact target
        self.nonce       = nonce

    def serialize(self) -> bytes:
        return (
            struct.pack("<I", self.version) +
            bytes.fromhex(self.prev_hash)[::-1] +      # little-endian
            bytes.fromhex(self.merkle_root)[::-1] +
            struct.pack("<I", self.timestamp) +
            struct.pack("<I", self.bits) +
            struct.pack("<I", self.nonce)
        )

    def hash(self) -> str:
        """SHA-256d of the 80-byte header, returned as hex (big-endian display)."""
        raw = sha256d(self.serialize())
        return raw[::-1].hex()   # reverse to big-endian for display

    @property
    def target(self) -> int:
        """Expand compact 'bits' to full 256-bit target integer."""
        exponent = (self.bits >> 24) & 0xFF
        mantissa = self.bits & 0x007FFFFF
        return mantissa * (256 ** (exponent - 3))

    @property
    def work(self) -> int:
        """Estimated hashes required to produce this block."""
        t = self.target
        return (2**256 // (t + 1)) if t > 0 else 0

    def to_dict(self) -> dict:
        return {
            "version":     self.version,
            "prev_hash":   self.prev_hash,
            "merkle_root": self.merkle_root,
            "timestamp":   self.timestamp,
            "bits":        self.bits,
            "bits_hex":    f"{self.bits:08x}",
            "nonce":       self.nonce,
            "difficulty":  self.difficulty,
        }

    @property
    def difficulty(self) -> float:
        """Human-readable difficulty (relative to genesis difficulty)."""
        genesis_target = (0x00ffff * (256 ** (0x1d - 3)))
        return genesis_target / max(self.target, 1)

    @classmethod
    def from_dict(cls, d: dict) -> "BlockHeader":
        return cls(d["version"], d["prev_hash"], d["merkle_root"],
                   d["timestamp"], d["bits"], d["nonce"])


# ═══════════════════════════════════════════════════════════════════════
#  BLOCK
# ═══════════════════════════════════════════════════════════════════════

class Block:
    def __init__(self, header: BlockHeader, transactions: List[Transaction],
                 height: int = 0):
        self.header       = header
        self.transactions = transactions
        self.height       = height
        self._hash: Optional[str] = None

    @property
    def hash(self) -> str:
        if self._hash is None:
            self._hash = self.header.hash()
        return self._hash

    def invalidate_hash(self):
        self._hash = None

    @staticmethod
    def compute_merkle_root(txids: List[str]) -> str:
        """
        Bitcoin-compatible Merkle tree.
        Duplicate last element when count is odd.
        """
        if not txids:
            return "0" * 64
        hashes = [bytes.fromhex(txid)[::-1] for txid in txids]
        while len(hashes) > 1:
            if len(hashes) % 2:
                hashes.append(hashes[-1])
            hashes = [
                sha256d(hashes[i] + hashes[i + 1])
                for i in range(0, len(hashes), 2)
            ]
        return hashes[0][::-1].hex()

    def update_merkle_root(self) -> str:
        txids = [tx.txid for tx in self.transactions]
        self.header.merkle_root = self.compute_merkle_root(txids)
        self._hash = None
        return self.header.merkle_root

    @property
    def size(self) -> int:
        return sum(tx.size for tx in self.transactions) + BlockHeader.SIZE

    @property
    def tx_count(self) -> int:
        return len(self.transactions)

    @property
    def total_fees(self) -> int:
        """Total fees = coinbase reward - block subsidy (approximation)."""
        if not self.transactions or not self.transactions[0].is_coinbase:
            return 0
        subsidy = block_subsidy(self.height)
        coinbase_out = sum(o.value for o in self.transactions[0].outputs)
        return max(0, coinbase_out - subsidy)

    def to_dict(self, include_txs: bool = True) -> dict:
        d = {
            "hash":      self.hash,
            "height":    self.height,
            "header":    self.header.to_dict(),
            "tx_count":  self.tx_count,
            "size":      self.size,
            "work":      str(self.header.work),
        }
        if include_txs:
            d["transactions"] = [tx.to_dict() for tx in self.transactions]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Block":
        header = BlockHeader.from_dict(d["header"])
        txs    = [Transaction.from_dict(t) for t in d.get("transactions", [])]
        block  = cls(header, txs, d["height"])
        block._hash = d.get("hash")
        return block


# ═══════════════════════════════════════════════════════════════════════
#  DIFFICULTY / TARGET
# ═══════════════════════════════════════════════════════════════════════

def target_to_bits(target: int) -> int:
    """Convert 256-bit target to compact 'bits' representation."""
    h = f"{target:064x}"
    stripped = h.lstrip("0")
    if not stripped:
        return 0
    byte_len = (len(stripped) + 1) // 2
    significant = stripped[:6].ljust(6, "0")
    mantissa = int(significant, 16)
    if mantissa & 0x800000:
        mantissa >>= 8
        byte_len += 1
    return (byte_len << 24) | (mantissa & 0x007FFFFF)

def bits_to_target(bits: int) -> int:
    exponent = (bits >> 24) & 0xFF
    mantissa = bits & 0x007FFFFF
    return mantissa * (256 ** (exponent - 3))

def retarget(last_bits: int, actual_timespan: int) -> int:
    """
    Bitcoin-compatible difficulty retarget.
    Clamp adjustment to 4× in either direction.
    """
    expected = TARGET_BLOCK_TIME * DIFFICULTY_WINDOW
    actual   = max(expected // 4, min(actual_timespan, expected * 4))
    old_target = bits_to_target(last_bits)
    new_target = old_target * actual // expected
    # Do not exceed genesis target
    max_target = bits_to_target(GENESIS_BITS)
    new_target = min(new_target, max_target)
    return target_to_bits(new_target)

def block_subsidy(height: int) -> int:
    """Block reward in satoshis, halving every HALVING_INTERVAL blocks."""
    halvings = height // HALVING_INTERVAL
    if halvings >= 64:
        return 0
    return BLOCK_REWARD_INITIAL >> halvings


# ═══════════════════════════════════════════════════════════════════════
#  BLOCKCHAIN
# ═══════════════════════════════════════════════════════════════════════

class Blockchain:
    """
    Full blockchain with:
      - In-memory chain index (height → Block)
      - UTXO set management
      - Mempool
      - Chain reorganization
      - Orphan block handling
      - Checkpoint enforcement
      - Persistence to disk (JSON, LevelDB-ready)
    """

    def __init__(self, data_dir: str = "~/.vitocoin", network: str = "mainnet"):
        self.data_dir  = os.path.expanduser(data_dir)
        self.network   = network
        self.params    = COIN_PARAMS[network]
        self._lock     = threading.RLock()

        self.chain:       List[Block]      = []          # main chain (ordered)
        self.by_hash:     Dict[str, Block] = {}          # hash → Block index
        self.chain_hashes: set             = set()       # fast O(1) membership check
        self.orphans: collections.OrderedDict = collections.OrderedDict()  # LRU orphan pool
        self.utxo         = UTXOSet()
        self.mempool      = Mempool()
        self.chain_work:  int              = 0           # total accumulated PoW
        # Undo data: block_height → UTXO diff before that block was applied
        # Format: { height: {"spent": {key: (TxOutput, block_h, is_cb)}, "created": set(keys)} }
        # Capped at last MAX_UNDO_DEPTH entries to bound memory usage
        self._undo_data:  Dict[int, dict]  = {}
        self.MAX_UNDO_DEPTH = 1000                       # keep undo data for last 1000 blocks

        # ── Observability counters ──────────────────────────────────────
        self.stats_orphan_count: int   = 0      # total orphan blocks seen
        self.stats_reorg_count:  int   = 0      # total chain reorganizations
        # Propagation timing: rolling window of last 100 block/tx receive→accept times (ms)
        self._block_prop_times: list   = []     # list of float ms
        self._tx_prop_times:    list   = []     # list of float ms
        self._PROP_WINDOW       = 100
        # Block-acceptance callbacks: each callable receives (block)
        # after it is connected to the main chain.
        self.block_listeners: list = []

        os.makedirs(self.data_dir, exist_ok=True)
        # Open persistent store (LevelDB primary, SQLite fallback)
        self._store: ChainStore = open_store(self.data_dir)
        self._init_chain()

    # ── Initialization ─────────────────────────────────────────────────

    def _init_chain(self):
        """
        Load chain from store.  Falls back to JSON (one-version migration
        compatibility) if store is empty but chain.json exists.
        """
        tip_hash = self._store.get_meta("tip_hash")
        if tip_hash:
            try:
                self._load_chain_from_store()
                log.info("📂  Loaded chain from store: height=%d, hash=%s…",
                         self.height, self.tip.hash[:16])
                return
            except Exception as e:
                log.warning("Store load failed (%s) — attempting JSON fallback", e)

        # ── JSON migration fallback (one-version compatibility) ────────
        chain_file = os.path.join(self.data_dir, "chain.json")
        if os.path.exists(chain_file):
            try:
                self._migrate_from_json(chain_file)
                log.info("📦  Migrated from JSON: height=%d", self.height)
                return
            except Exception as e:
                log.warning("JSON migration failed (%s) — rebuilding from genesis", e)

        # ── Fresh genesis ──────────────────────────────────────────────
        genesis = self._create_genesis()
        self.chain.append(genesis)
        self.by_hash[genesis.hash]  = genesis
        self.chain_hashes.add(genesis.hash)
        self.utxo.apply_block(genesis.transactions, 0)
        self.chain_work = genesis.header.work
        # Persist genesis immediately
        self._store_block(genesis)
        self._store_utxo_full()
        self._store.put_meta("tip_hash",   genesis.hash)
        self._store.put_meta("chain_work", str(self.chain_work))
        self._store.put_meta("network",    self.network)
        log.info("🌱  Genesis: %s", genesis.hash)

    def _create_genesis(self) -> Block:
        """
        Create the VitoCoin genesis block.
        Genesis message encoded in coinbase (like Bitcoin's Times headline).
        """
        from vitocoin.crypto import PrivateKey
        # Deterministic genesis key — NOT for spending, just to have a valid address
        genesis_key = PrivateKey(hashlib.sha256(b"VitoCoin Genesis Block 2024").digest())
        genesis_addr = genesis_key.public_key.to_address()

        coinbase = Transaction.coinbase(genesis_addr, 0, BLOCK_REWARD_INITIAL, extra_nonce=0)
        # Encode genesis message in coinbase scriptSig
        msg = b"VitoCoin: The Future of Decentralized Finance - 2024"
        coinbase.inputs[0].script_sig = (
            bytes([len(msg)]) + msg + b"\x04\xff\xff\x00\x1d\x01\x04"
        )
        coinbase._txid = None  # recompute after modifying script

        merkle = Block.compute_merkle_root([coinbase.txid])
        header = BlockHeader(
            version     = 1,
            prev_hash   = "0" * 64,
            merkle_root = merkle,
            timestamp   = GENESIS_TIMESTAMP,
            bits        = GENESIS_BITS,
            nonce       = GENESIS_NONCE,
        )
        # For testnet / dev: accept genesis without valid PoW
        genesis = Block(header, [coinbase], height=0)
        genesis._hash = genesis.hash
        return genesis

    # ── Chain Access ───────────────────────────────────────────────────

    @property
    def height(self) -> int:
        return self.chain[-1].height if self.chain else 0

    @property
    def tip(self) -> Optional[Block]:
        return self.chain[-1] if self.chain else None

    def get_block_by_height(self, height: int) -> Optional[Block]:
        if 0 <= height < len(self.chain):
            return self.chain[height]
        return None

    def get_block_by_hash(self, h: str) -> Optional[Block]:
        return self.by_hash.get(h)

    def get_tx(self, txid: str) -> Optional[Transaction]:
        """
        O(1) transaction lookup via tx index (store key x:<txid>).
        Falls back to mempool, then to linear scan for unmigrated chains.
        """
        # Check mempool first (not yet confirmed)
        if txid in self.mempool:
            return self.mempool._txs[txid]

        # O(1) store lookup
        loc_raw = self._store.get(key_tx_index(txid))
        if loc_raw is not None:
            loc = json.loads(loc_raw)
            block_hash_raw = self._store.get(key_block_height(loc["h"]))
            if block_hash_raw is not None:
                block_hash = block_hash_raw.decode()
                # Try in-memory chain first (fast path)
                blk = self.by_hash.get(block_hash)
                if blk is not None:
                    idx = loc["i"]
                    if 0 <= idx < len(blk.transactions):
                        return blk.transactions[idx]
                # Load from store (block may not be in memory)
                blk = self._load_block_by_hash(block_hash)
                if blk is not None:
                    idx = loc["i"]
                    if 0 <= idx < len(blk.transactions):
                        return blk.transactions[idx]

        # Legacy linear fallback for chains not yet indexed (removed after full migration)
        for block in reversed(self.chain[-1000:]):
            for tx in block.transactions:
                if tx.txid == txid:
                    return tx
        return None

    # ── Block Acceptance ───────────────────────────────────────────────

    def add_block(self, block: Block) -> Tuple[bool, str]:
        with self._lock:
            # Already known?
            if block.hash in self.by_hash:
                return False, "Already known"

            # Validate header
            ok, reason = self._validate_header(block)
            if not ok:
                return False, reason

            # Extends main chain?
            if block.header.prev_hash == self.tip.hash:
                ok, reason = self._validate_block(block, self.height + 1)
                if not ok:
                    return False, reason
                _t0 = time.time()
                self._connect_block(block)
                _accept_ms = (time.time() - _t0) * 1000
                self._block_prop_times.append(_accept_ms)
                if len(self._block_prop_times) > self._PROP_WINDOW:
                    self._block_prop_times.pop(0)
                self._try_reconnect_orphans()
                self._save_chain()
                return True, "Accepted"

            # Potential chain reorg?
            if block.header.prev_hash in self.by_hash:
                prev = self.by_hash[block.header.prev_hash]
                # Check if this fork has more accumulated work
                fork_work = self._compute_fork_work(block)
                if fork_work > self.chain_work:
                    log.warning(f"⚠️  Chain reorg detected at height {prev.height + 1}")
                    ok = self._reorganize(block)
                    if ok:
                        return True, "Accepted (reorg)"
                else:
                    # Store in orphan pool and also in by_hash so subsequent
                    # fork blocks can chain off this one.  Then try to reconnect
                    # orphans: once the full fork chain accumulates enough work
                    # it will trigger a reorg on the next call.
                    self.orphans[block.hash] = block
                    self.by_hash[block.hash] = block
                    self.stats_orphan_count += 1
                    self._evict_orphans()
                    self._try_reconnect_orphans()
                    return False, "Orphan (less work)"

            # Orphan — we don't have its parent yet
            self.orphans[block.hash] = block
            self.stats_orphan_count += 1
            self._evict_orphans()
            log.info(f"📦  Orphan block {block.hash[:16]}… (missing parent)")
            return False, "Orphan"

    def _validate_header(self, block: Block) -> Tuple[bool, str]:
        h = block.hash

        # PoW check — hash must be less than target
        target = block.header.target
        hash_int = int(h, 16)
        if hash_int > target:
            return False, f"Insufficient PoW: {h[:16]}… > target"

        # Timestamp checks
        now = int(time.time())
        if block.header.timestamp > now + MAX_FUTURE_BLOCK_TIME:
            return False, "Block timestamp too far in future"
        mtp = self._median_time_past()
        if block.header.timestamp <= mtp:
            return False, f"Block timestamp {block.header.timestamp} ≤ MTP {mtp}"

        # Bits must match expected difficulty
        expected_bits = self._next_bits()
        if block.header.bits != expected_bits:
            return False, f"Wrong difficulty bits: {block.header.bits:08x} ≠ {expected_bits:08x}"

        return True, "OK"

    def _validate_block(self, block: Block, expected_height: int) -> Tuple[bool, str]:
        # Height check — reject mismatched height; never silently mutate an incoming block
        if block.height != 0 and block.height != expected_height:
            return False, f"Block height mismatch: got {block.height}, expected {expected_height}"
        # For newly-mined blocks that arrive with height=0 (not yet set), accept and set height
        if block.height == 0 and expected_height != 0:
            block.height = expected_height

        # Size check comes early — cheap guard before expensive UTXO lookups
        if block.size > MAX_BLOCK_SIZE:
            return False, f"Block too large: {block.size} bytes"

        # Must have transactions
        if not block.transactions:
            return False, "Empty block"

        # First transaction must be coinbase
        if not block.transactions[0].is_coinbase:
            return False, "First transaction must be coinbase"

        # Only one coinbase
        for tx in block.transactions[1:]:
            if tx.is_coinbase:
                return False, "Multiple coinbase transactions"

        # Validate coinbase reward
        subsidy  = block_subsidy(expected_height)
        fees     = self._compute_fees(block.transactions[1:])
        max_reward = subsidy + fees
        cb_out  = sum(o.value for o in block.transactions[0].outputs)
        if cb_out > max_reward:
            return False, f"Coinbase reward too large: {cb_out} > {max_reward}"

        # Merkle root
        expected_merkle = Block.compute_merkle_root([tx.txid for tx in block.transactions])
        if block.header.merkle_root != expected_merkle:
            return False, "Merkle root mismatch"

        # Validate all non-coinbase transactions
        spent_in_block = set()  # within-block double-spend guard (F-07)
        for tx in block.transactions[1:]:
            ok, reason = tx.validate_syntax()
            if not ok:
                return False, f"TX {tx.txid[:12]}: {reason}"
            # Build UTXO dict for script validation — reject if any input UTXO is missing
            utxo_dict: dict = {}
            for inp in tx.inputs:
                key = (inp.prev_txid, inp.prev_index)
                if key in spent_in_block:
                    raise ValueError(
                        f"Within-block double-spend detected: "
                        f"{inp.prev_txid}:{inp.prev_index}"
                    )
                spent_in_block.add(key)
                utxo_out = self.utxo.get(inp.prev_txid, inp.prev_index)
                if utxo_out is None:
                    return False, f"TX {tx.txid[:12]}: UTXO not found {inp.prev_txid[:12]}:{inp.prev_index}"
                utxo_dict[f"{inp.prev_txid}:{inp.prev_index}"] = utxo_out
            ok, reason = tx.validate_scripts(utxo_dict)
            if not ok:
                return False, f"TX script {tx.txid[:12]}: {reason}"

        # Checkpoint enforcement
        checkpoints = self.params.get("checkpoints", {})
        if expected_height in checkpoints:
            if block.hash != checkpoints[expected_height]:
                return False, f"Checkpoint mismatch at height {expected_height}"

        return True, "OK"

    def _connect_block(self, block: Block) -> None:
        block.height = self.height + 1

        # ── Capture undo-diff BEFORE applying the block (T1.4) ──────────
        # Store only the delta: which outputs are spent + which are created.
        # This allows efficient rollback without storing the full UTXO set snapshot.
        spent_outputs = {}
        for tx in block.transactions:
            if not tx.is_coinbase:
                for inp in tx.inputs:
                    key = f"{inp.prev_txid}:{inp.prev_index}"
                    entry = self.utxo._utxos.get(key)
                    if entry is not None:
                        spent_outputs[key] = entry  # save (TxOutput, block_h, is_cb)
        created_keys = set()
        for tx in block.transactions:
            for idx in range(len(tx.outputs)):
                if not tx.outputs[idx].is_op_return:
                    created_keys.add(f"{tx.txid}:{idx}")

        undo = {
            "spent":   spent_outputs,   # UTXOs this block consumed
            "created": created_keys,    # UTXO keys this block created
        }
        self._undo_data[block.height] = undo
        # Evict oldest undo entries to stay within memory cap
        if len(self._undo_data) > self.MAX_UNDO_DEPTH:
            oldest = min(self._undo_data)
            del self._undo_data[oldest]
            self._delete_undo(oldest)   # also evict from store
            log.debug("Evicted undo data for block #%d", oldest)

        # ── Apply block to UTXO set and chain state ──────────────────────
        self.chain.append(block)
        self.by_hash[block.hash]   = block
        self.chain_hashes.add(block.hash)             # O(1) membership tracking
        self.utxo.apply_block(block.transactions, block.height)
        self.chain_work += block.header.work
        self.mempool.remove_confirmed([tx.txid for tx in block.transactions])

        # ── Persist: block + UTXO deltas + undo + tx index ──────────────
        # Build a single atomic batch for this block
        store_pairs = []
        store_deletes = []

        # Block header + body + height index
        import json as _json
        store_pairs += [
            (key_block_header(block.hash),
             _json.dumps(block.header.to_dict(), separators=(",", ":")).encode()),
            (key_block_body(block.hash),
             _json.dumps({"height": block.height,
                          "transactions": [tx.to_dict() for tx in block.transactions]},
                         separators=(",", ":")).encode()),
            (key_block_height(block.height), block.hash.encode()),
        ]

        # Tx index: txid → (block_height, tx_index_in_block)
        for tx_i, tx in enumerate(block.transactions):
            store_pairs.append((
                key_tx_index(tx.txid),
                _json.dumps({"h": block.height, "i": tx_i},
                            separators=(",", ":")).encode(),
            ))

        # UTXO deltas: delete spent, write created
        for raw_key in spent_outputs:
            txid, idx = raw_key.rsplit(":", 1)
            store_deletes.append(key_utxo(txid, int(idx)))
        for raw_key in created_keys:
            txid, idx = raw_key.rsplit(":", 1)
            entry = self.utxo._utxos.get(raw_key)
            if entry is not None:
                out, h, is_cb = entry
                store_pairs.append((
                    key_utxo(txid, int(idx)),
                    _json.dumps({"v": out.value, "s": out.script_pubkey.hex(),
                                 "h": h, "cb": is_cb},
                                separators=(",", ":")).encode(),
                ))

        # Undo diff
        serializable_undo = {
            "spent": {
                k: {"v": e[0].value, "s": e[0].script_pubkey.hex(), "h": e[1], "cb": e[2]}
                for k, e in spent_outputs.items()
            },
            "created": list(created_keys),
        }
        store_pairs.append((
            key_undo(block.height),
            _json.dumps(serializable_undo, separators=(",", ":")).encode(),
        ))

        # Chain metadata
        store_pairs += [
            (key_meta("tip_hash"),   block.hash.encode()),
            (key_meta("chain_work"), str(self.chain_work).encode()),
            (key_meta("height"),     str(block.height).encode()),
        ]

        self._store.write_batch(store_pairs, store_deletes)

        log.info(
            "✅  Block #%d | %s… | %d txs | diff=%.2f",
            block.height, block.hash[:16], block.tx_count, block.header.difficulty,
        )


        # Notify block listeners
        for _cb in list(self.block_listeners):
            try:
                _cb(block)
            except Exception as _e:
                log.warning("block_listener error: %s", _e)
    def _reorganize(self, new_tip: Block) -> bool:
        """
        Full chain reorganization to a longer fork.

        Algorithm:
          1. Walk fork chain backward until we find a block that IS on the main chain
             (uses self.chain_hashes for O(1) lookup — no object identity issue)
          2. Save a UTXO safety snapshot before mutating anything
          3. Disconnect main chain blocks above the common ancestor using undo-diffs
          4. Connect fork blocks
          5. On any failure, restore the safety snapshot and reconnect disconnected blocks

        This implementation:
          - Avoids the O(n) UTXO full-replay of the original code
          - Avoids the object-identity bug in the ancestor-walking condition
          - Is safe against partial failures (atomically reverts on error)
        """
        log.warning("⚠️  Reorg: walking fork to find common ancestor")

        # ── Step 1: Walk fork chain to find common ancestor ──────────────
        fork_chain: List[Block] = []
        b = new_tip
        max_walk = len(self.chain) + 1  # guard against infinite loops
        steps = 0
        while b.hash not in self.chain_hashes:   # O(1) set lookup — no identity bug
            fork_chain.insert(0, b)
            prev = self.by_hash.get(b.header.prev_hash)
            if prev is None:
                log.error("Reorg: cannot find parent %s in index", b.header.prev_hash[:16])
                return False
            b = prev
            steps += 1
            if steps > max_walk:
                log.error("Reorg: ancestor walk exceeded chain length — aborting")
                return False

        common        = b
        common_height = common.height
        reorg_depth   = self.height - common_height
        if reorg_depth > MAX_REORG_DEPTH:
            log.error(
                "Reorg: depth %d exceeds MAX_REORG_DEPTH=%d — rejecting to prevent DoS",
                reorg_depth, MAX_REORG_DEPTH,
            )
            return False
        log.warning("⚠️  Reorg: common ancestor at height %d, disconnecting %d blocks",
                    common_height, self.height - common_height)

        # ── Step 2: Pre-reorg safety snapshot ────────────────────────────
        pre_reorg_utxo        = UTXOSet()
        pre_reorg_utxo._utxos = dict(self.utxo._utxos)
        pre_reorg_chain_work  = self.chain_work
        pre_reorg_undo        = dict(self._undo_data)
        pre_reorg_chain_len   = len(self.chain)

        # ── Step 3: Disconnect main chain blocks above common ancestor ───
        disconnected: List[Block] = []
        while self.height > common_height:
            victim = self.chain.pop()
            self.chain_hashes.discard(victim.hash)      # keep chain_hashes in sync
            self.chain_work -= victim.header.work

            # Rollback UTXO using undo-diff (efficient, no full replay)
            undo = self._undo_data.pop(victim.height, None)
            if undo is None:
                # Try loading from store before falling back
                undo = self._load_undo(victim.height)

            if undo is not None:
                # Remove created outputs (in-memory + store)
                utxo_deletes = []
                for raw_key in undo["created"]:
                    self.utxo._utxos.pop(raw_key, None)
                    txid, idx = raw_key.rsplit(":", 1)
                    utxo_deletes.append(key_utxo(txid, int(idx)))
                # Restore spent outputs (in-memory + store)
                utxo_pairs = []
                self.utxo._utxos.update(undo["spent"])
                for raw_key, entry in undo["spent"].items():
                    txid, idx = raw_key.rsplit(":", 1)
                    out, h, is_cb = entry
                    utxo_pairs.append((
                        key_utxo(txid, int(idx)),
                        json.dumps({"v": out.value, "s": out.script_pubkey.hex(),
                                    "h": h, "cb": is_cb},
                                   separators=(",", ":")).encode(),
                    ))
                # Remove tx index entries for this block
                tx_index_deletes = [key_tx_index(tx.txid) for tx in victim.transactions]
                self._store.write_batch(utxo_pairs,
                                        utxo_deletes + tx_index_deletes)
                self._delete_undo(victim.height)
                log.debug("Rolled back UTXO diff for block #%d", victim.height)
            else:
                log.warning("No undo data for block #%d — falling back to full UTXO replay",
                            victim.height)
                # Fallback: rebuild UTXO from remaining chain (slower but correct)
                self.utxo = UTXOSet()
                for bc in self.chain:
                    self.utxo.apply_block(bc.transactions, bc.height)

            # Return transactions to mempool
            for tx in victim.transactions[1:]:
                self.mempool._txs[tx.txid] = tx
            disconnected.append(victim)
            log.info("🔄  Disconnected block #%d (%s…)", victim.height, victim.hash[:16])

        # ── Step 4: Connect fork blocks ───────────────────────────────────
        for fork_block in fork_chain:
            ok, reason = self._validate_block(fork_block, self.height + 1)
            if not ok:
                log.error("Reorg: fork block #%d failed validation: %s", fork_block.height, reason)
                # ── Rollback: restore pre-reorg state ─────────────────────
                self.utxo._utxos    = dict(pre_reorg_utxo._utxos)
                self.chain_work     = pre_reorg_chain_work
                self._undo_data     = pre_reorg_undo
                # Reconnect the disconnected main chain blocks
                del self.chain[common_height + 1:]
                for d in reversed(disconnected):
                    self.chain.append(d)
                    self.chain_hashes.add(d.hash)
                    self.chain_work += d.header.work
                log.warning("Reorg rolled back — main chain restored to height %d", self.height)
                return False
            self._connect_block(fork_block)

        self.stats_reorg_count += 1
        log.warning("✅  Reorg complete: new tip #%d %s…", self.height, self.tip.hash[:16])
        return True

    def _evict_orphans(self) -> None:
        """Evict the oldest orphan(s) when the pool exceeds MAX_ORPHANS (LRU).

        Uses OrderedDict insertion order — the first entry is always the oldest.
        Also removes evicted orphan from by_hash if nothing else references it.
        """
        while len(self.orphans) > MAX_ORPHANS:
            evicted_hash, _ = self.orphans.popitem(last=False)  # FIFO (oldest first)
            # Remove from by_hash only if it's not on the main chain
            if evicted_hash not in self.chain_hashes:
                self.by_hash.pop(evicted_hash, None)
            log.debug("🗑  Evicted orphan %s… (pool full)", evicted_hash[:16])

    def _try_reconnect_orphans(self) -> None:
        """Try to attach orphan blocks now that we may have their parents.

        Considers both main-chain extension AND fork reconnection so that
        a sequence of fork blocks arriving out-of-order can eventually
        trigger a reorg once all blocks in the fork are present.
        """
        changed = True
        while changed:
            changed = False
            for h, orphan in list(self.orphans.items()):
                prev_known = (orphan.header.prev_hash == self.tip.hash or
                              orphan.header.prev_hash in self.by_hash)
                if prev_known:
                    del self.orphans[h]
                    ok, reason = self.add_block(orphan)
                    if ok:
                        changed = True
                        break

    # ── Difficulty ─────────────────────────────────────────────────────

    def _next_bits(self) -> int:
        """Compute expected bits for the next block."""
        height = self.height
        if height == 0 or (height + 1) % DIFFICULTY_WINDOW != 0:
            return self.tip.header.bits if self.tip else GENESIS_BITS
        # Retarget
        first = self.chain[-(DIFFICULTY_WINDOW)]
        last  = self.chain[-1]
        actual_span = last.header.timestamp - first.header.timestamp
        new_bits = retarget(last.header.bits, actual_span)
        log.info(f"🎯  Difficulty retarget at #{height+1}: {self.tip.header.bits:08x} → {new_bits:08x}")
        return new_bits

    def _median_time_past(self) -> int:
        """Median timestamp of last 11 blocks (BIP-68/113)."""
        recent = [b.header.timestamp for b in self.chain[-MEDIAN_TIME_PAST_N:]]
        if not recent:
            return 0
        return sorted(recent)[len(recent) // 2]

    # ── Helpers ────────────────────────────────────────────────────────

    def _compute_fees(self, txs: List[Transaction]) -> int:
        """Compute total fees for a list of transactions (simplified)."""
        total = 0
        for tx in txs:
            input_val  = sum(
                (self.utxo.get(i.prev_txid, i.prev_index) or TxOutput(0, b"")).value
                for i in tx.inputs
            )
            output_val = sum(o.value for o in tx.outputs)
            total += max(0, input_val - output_val)
        return total

    def _compute_fork_work(self, block: Block) -> int:
        """Estimate total work for a fork ending at block."""
        work = block.header.work
        b = self.by_hash.get(block.header.prev_hash)
        while b and b not in self.chain:
            work += b.header.work
            b = self.by_hash.get(b.header.prev_hash)
        if b and b in self.chain:
            idx = self.chain.index(b)
            work += sum(bb.header.work for bb in self.chain[:idx+1])
        return work

    # ── Summary ────────────────────────────────────────────────────────

    def propagation_stats(self) -> dict:
        """Return observability metrics for the /metrics endpoint."""
        def _avg(lst):
            return round(sum(lst) / len(lst), 3) if lst else 0.0

        def _p99(lst):
            if not lst:
                return 0.0
            s = sorted(lst)
            idx = max(0, int(len(s) * 0.99) - 1)
            return round(s[idx], 3)

        return {
            "block_prop_avg_ms": _avg(self._block_prop_times),
            "block_prop_p99_ms": _p99(self._block_prop_times),
            "tx_prop_avg_ms":    _avg(self._tx_prop_times),
            "tx_prop_p99_ms":    _p99(self._tx_prop_times),
            "orphan_count":      self.stats_orphan_count,
            "reorg_count":       self.stats_reorg_count,
        }

    def summary(self) -> dict:
        tip = self.tip
        return {
            "height":        self.height,
            "best_hash":     tip.hash if tip else "0" * 64,
            "difficulty":    tip.header.difficulty if tip else 1.0,
            "bits":          f"{tip.header.bits:08x}" if tip else f"{GENESIS_BITS:08x}",
            "chain_work":    str(self.chain_work),
            "mempool_count": len(self.mempool),
            "utxo_count":    self.utxo.count,
            "supply_vito":   self.utxo.total_supply / COIN,
            "network":       self.network,
            "version":       VERSION,
            "next_halving_blocks": HALVING_INTERVAL - (self.height % HALVING_INTERVAL),
            "block_reward":  block_subsidy(self.height) / COIN,
        }

    # ── Persistence ────────────────────────────────────────────────────

    def _store_block(self, block: "Block") -> None:
        """Write block header + body + height index to store."""
        pairs = [
            (key_block_header(block.hash), json.dumps(block.header.to_dict(),
                                                       separators=(",", ":")).encode()),
            (key_block_body(block.hash),   json.dumps(
                {"height": block.height,
                 "transactions": [tx.to_dict() for tx in block.transactions]},
                separators=(",", ":")).encode()),
            (key_block_height(block.height), block.hash.encode()),
        ]
        self._store.write_batch(pairs)

    def _load_block_by_hash(self, block_hash: str) -> Optional["Block"]:
        """Load a full block from store by hash."""
        body_raw = self._store.get(key_block_body(block_hash))
        if body_raw is None:
            return None
        body = json.loads(body_raw)
        hdr_raw = self._store.get(key_block_header(block_hash))
        if hdr_raw is None:
            return None
        hdr = BlockHeader.from_dict(json.loads(hdr_raw))
        txs = [Transaction.from_dict(t) for t in body["transactions"]]
        blk = Block(hdr, txs, body["height"])
        blk._hash = block_hash
        return blk

    def _store_utxo_entry(self, txid: str, index: int,
                           entry: Tuple) -> None:
        """Persist a single UTXO entry (TxOutput, height, is_coinbase)."""
        out, h, is_cb = entry
        self._store.put(
            key_utxo(txid, index),
            json.dumps({"v": out.value, "s": out.script_pubkey.hex(),
                        "h": h, "cb": is_cb},
                       separators=(",", ":")).encode(),
        )

    def _delete_utxo_entry(self, txid: str, index: int) -> None:
        self._store.delete(key_utxo(txid, index))

    def _store_utxo_full(self) -> None:
        """Bulk-write entire in-memory UTXO set to store (used during genesis/migration)."""
        pairs = []
        for raw_key, (out, h, is_cb) in self.utxo._utxos.items():
            txid, idx = raw_key.rsplit(":", 1)
            pairs.append((
                key_utxo(txid, int(idx)),
                json.dumps({"v": out.value, "s": out.script_pubkey.hex(),
                            "h": h, "cb": is_cb},
                           separators=(",", ":")).encode(),
            ))
        if pairs:
            self._store.write_batch(pairs)

    def _load_utxo_from_store(self) -> None:
        """Restore in-memory UTXO set from store."""
        from vitocoin.transaction import TxOutput as _TxOut
        self.utxo = UTXOSet()
        for raw_k, raw_v in self._store.iter_prefix(b"u:"):
            # key format: b"u:<txid>:<idx>"
            parts = raw_k.decode().split(":", 2)   # "u", txid, idx
            txid, idx = parts[1], int(parts[2])
            d = json.loads(raw_v)
            out = _TxOut(d["v"], bytes.fromhex(d["s"]))
            self.utxo._utxos[f"{txid}:{idx}"] = (out, d["h"], d["cb"])

    def _store_undo(self, height: int, undo: dict) -> None:
        """Persist undo-diff for a block height."""
        # Serialize: spent keys map value tuples, created is a list
        serializable = {
            "spent": {
                k: {"v": e[0].value, "s": e[0].script_pubkey.hex(), "h": e[1], "cb": e[2]}
                for k, e in undo["spent"].items()
            },
            "created": list(undo["created"]),
        }
        self._store.put(
            key_undo(height),
            json.dumps(serializable, separators=(",", ":")).encode(),
        )

    def _delete_undo(self, height: int) -> None:
        self._store.delete(key_undo(height))

    def _load_undo(self, height: int) -> Optional[dict]:
        """Load undo-diff for a block height from store."""
        from vitocoin.transaction import TxOutput as _TxOut
        raw = self._store.get(key_undo(height))
        if raw is None:
            return None
        d = json.loads(raw)
        spent = {}
        for k, e in d["spent"].items():
            spent[k] = (_TxOut(e["v"], bytes.fromhex(e["s"])), e["h"], e["cb"])
        return {"spent": spent, "created": set(d["created"])}

    def _store_tx_index(self, tx: "Transaction", block_height: int, tx_index: int) -> None:
        """Index: txid → {h: block_height, i: tx_index}."""
        self._store.put(
            key_tx_index(tx.txid),
            json.dumps({"h": block_height, "i": tx_index}, separators=(",", ":")).encode(),
        )

    def _delete_tx_index(self, txid: str) -> None:
        self._store.delete(key_tx_index(txid))

    def _save_chain(self) -> None:
        """
        Persist updated chain metadata (tip + chain_work).
        Individual block/UTXO/undo writes happen incrementally in _connect_block
        and _reorganize, so this only needs to flush the tip pointer.
        """
        try:
            self._store.write_batch([
                (key_meta("tip_hash"),   self.tip.hash.encode()),
                (key_meta("chain_work"), str(self.chain_work).encode()),
                (key_meta("network"),    self.network.encode()),
                (key_meta("height"),     str(self.height).encode()),
            ])
        except Exception as e:
            log.error("Chain save failed: %s", e)

    def _load_chain_from_store(self) -> None:
        """
        Restore chain state from the persistent store.
        Walks from tip back to genesis by following prev_hash links,
        then reverses to build the ordered chain list.
        """
        tip_hash   = self._store.get_meta("tip_hash")
        chain_work = int(self._store.get_meta("chain_work") or "0")
        if not tip_hash:
            raise ValueError("No tip_hash in store")

        # Walk backward from tip to genesis
        blocks = []
        h = tip_hash
        visited = set()
        while h and h != "0" * 64:
            if h in visited:
                raise ValueError(f"Cycle detected at {h[:16]}")
            visited.add(h)
            blk = self._load_block_by_hash(h)
            if blk is None:
                raise ValueError(f"Missing block {h[:16]} in store")
            blocks.append(blk)
            h = blk.header.prev_hash

        blocks.reverse()   # genesis first

        self.chain        = blocks
        self.chain_work   = chain_work
        self.by_hash      = {b.hash: b for b in blocks}
        self.chain_hashes = {b.hash for b in blocks}

        # Restore UTXO set from store (already built incrementally)
        self._load_utxo_from_store()

        log.info("ChainStore load: %d blocks, %d UTXOs",
                 len(blocks), self.utxo.count)

    def _migrate_from_json(self, json_path: str) -> None:
        """
        One-version migration: read chain.json, import into ChainStore.
        After import the store is the authoritative source and json is left
        in place (but no longer written to) for one version's backward compat.
        """
        log.info("Migrating chain.json → ChainStore …")
        with open(json_path) as f:
            data = json.load(f)
        blocks = [Block.from_dict(b) for b in data["blocks"]]

        self.chain        = blocks
        self.chain_work   = int(data.get("chain_work", 0))
        self.by_hash      = {b.hash: b for b in blocks}
        self.chain_hashes = {b.hash for b in blocks}

        # Replay UTXO + build tx index during migration
        self.utxo = UTXOSet()
        for blk in blocks:
            self.utxo.apply_block(blk.transactions, blk.height)
            self._store_block(blk)
            for idx, tx in enumerate(blk.transactions):
                self._store_tx_index(tx, blk.height, idx)

        self._store_utxo_full()
        self._store.write_batch([
            (key_meta("tip_hash"),   blocks[-1].hash.encode()),
            (key_meta("chain_work"), str(self.chain_work).encode()),
            (key_meta("network"),    self.network.encode()),
            (key_meta("height"),     str(blocks[-1].height).encode()),
        ])
        log.info("Migration complete: %d blocks, %d UTXOs",
                 len(blocks), self.utxo.count)
