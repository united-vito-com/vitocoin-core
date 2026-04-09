"""
VitoCoin Mining Engine
============================================================
Full Proof-of-Work miner with:
  • Multi-threaded mining (uses all CPU cores)
  • getblocktemplate protocol (allows external miners / pool integration)
  • Dynamic nonce space partitioning per thread (no wasted work)
  • extranonce support for when 32-bit nonce space is exhausted
  • Real-time hashrate measurement with exponential moving average
  • Automatic block candidate refresh on new chain tip
  • Stratum-ready architecture (pool mining upgrade)
  • Fee-maximizing transaction selection
"""

import hashlib
import logging
import os
import struct
import threading
import time
from typing import Optional, Dict, List

from vitocoin.blockchain import Blockchain, Block, BlockHeader, block_subsidy, GENESIS_BITS
from vitocoin.transaction import Transaction, COIN
from vitocoin.crypto import sha256d

log = logging.getLogger("VitoCoin.miner")


# ── Constants ──────────────────────────────────────────────────────────
NONCE_MAX          = 0xFFFFFFFF
HASHRATE_SMOOTHING = 0.1         # EMA alpha for hashrate measurement
CANDIDATE_REFRESH  = 30          # Max seconds before refreshing candidate block
THREAD_COUNT       = max(1, os.cpu_count() or 1)


# ═══════════════════════════════════════════════════════════════════════
#  MINING WORKER
# ═══════════════════════════════════════════════════════════════════════

class MiningWorker:
    """Single-threaded mining loop operating over a nonce subrange."""

    def __init__(self, worker_id: int, miner: "Miner"):
        self.worker_id   = worker_id
        self.miner       = miner
        self.hashes      = 0
        self.running     = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        self.running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name=f"miner-worker-{self.worker_id}"
        )
        self._thread.start()

    def stop(self):
        self.running = False

    def _loop(self):
        while self.running:
            candidate = self.miner.get_candidate()
            if candidate is None:
                time.sleep(0.01)
                continue
            block, target_int = candidate
            self._mine(block, target_int)

    def _mine(self, block: Block, target_int: int):
        """
        Inner PoW loop — tight SHA-256d computation.
        Each worker handles a nonce subrange based on its worker_id.
        """
        num_workers  = self.miner.num_workers
        start_nonce  = (NONCE_MAX // num_workers) * self.worker_id
        end_nonce    = (NONCE_MAX // num_workers) * (self.worker_id + 1)
        header       = block.header
        extra_nonce  = self.miner.extra_nonce

        for nonce in range(start_nonce, end_nonce):
            if not self.running:
                return
            if self.miner.should_refresh(block):
                return

            header.nonce = nonce
            raw  = header.serialize()
            h    = sha256d(raw)
            hash_int = int.from_bytes(h[::-1], "big")  # display byte order, matches blockchain._validate_header
            self.hashes += 1

            if hash_int <= target_int:
                # FOUND A BLOCK!
                block._hash = h[::-1].hex()
                block.height = self.miner.chain.height + 1
                self.miner.on_block_found(block)
                return

        # Nonce space exhausted — increment extra nonce and retry
        self.miner.increment_extra_nonce()


# ═══════════════════════════════════════════════════════════════════════
#  MINER
# ═══════════════════════════════════════════════════════════════════════

class Miner:
    def __init__(self, blockchain: Blockchain, wallet_address: str,
                 num_threads: int = THREAD_COUNT):
        self.chain         = blockchain
        self.wallet        = wallet_address
        self.num_workers   = num_threads

        self._candidate: Optional[Block] = None
        self._candidate_tip_hash: str    = ""
        self._candidate_time: float      = 0.0
        self._candidate_lock             = threading.RLock()

        self.extra_nonce   = 0
        self._workers: List[MiningWorker] = []
        self._running      = False

        # Stats
        self._hashrate     = 0.0       # EMA hashrate (H/s)
        self._total_hashes = 0
        self._blocks_found = 0
        self._start_time   = 0.0
        self._stats_lock   = threading.Lock()

        # Callback: called when a block is found (set by node)
        self.on_block_found_cb = None

    # ── Lifecycle ──────────────────────────────────────────────────────

    def start(self):
        if self._running:
            return
        self._running   = True
        self._start_time = time.time()
        self._workers   = [MiningWorker(i, self) for i in range(self.num_workers)]
        for w in self._workers:
            w.start()
        threading.Thread(target=self._stats_loop, daemon=True, name="miner-stats").start()
        log.info(f"⛏  Mining started | {self.num_workers} threads | wallet={self.wallet[:20]}…")

    def stop(self):
        self._running = False
        for w in self._workers:
            w.stop()
        log.info(f"⛏  Mining stopped | blocks_found={self._blocks_found} | total_hashes={self._total_hashes:,}")

    # ── Candidate block management ─────────────────────────────────────

    def get_candidate(self) -> Optional[tuple]:
        """Return (block, target_int) for workers to mine."""
        with self._candidate_lock:
            tip = self.chain.tip
            tip_hash = tip.hash if tip else "genesis"

            # Rebuild candidate if chain tip changed or candidate is stale
            if (self._candidate is None or
                    self._candidate_tip_hash != tip_hash or
                    time.time() - self._candidate_time > CANDIDATE_REFRESH):
                self._build_candidate()

            if self._candidate is None:
                return None
            target_int = self._candidate.header.target
            return self._candidate, target_int

    def _build_candidate(self):
        """Construct a new block candidate from mempool + chain tip."""
        tip    = self.chain.tip
        height = (tip.height + 1) if tip else 1
        subsidy = block_subsidy(height)
        bits   = self.chain._next_bits()

        # Select transactions from mempool (fee-maximizing)
        pending = self.chain.mempool.get_block_template(max_bytes=3_900_000)

        # Build coinbase with extra_nonce in scriptSig
        coinbase = Transaction.coinbase(
            self.wallet, height,
            subsidy + self._estimate_fees(pending),
            extra_nonce=self.extra_nonce,
        )
        txs = [coinbase] + pending

        # Build block header
        merkle_root = Block.compute_merkle_root([tx.txid for tx in txs])
        header = BlockHeader(
            version     = 2,
            prev_hash   = tip.hash if tip else "0" * 64,
            merkle_root = merkle_root,
            timestamp   = int(time.time()),
            bits        = bits,
            nonce       = 0,
        )
        block = Block(header, txs)

        self._candidate           = block
        self._candidate_tip_hash  = tip.hash if tip else "0" * 64
        self._candidate_time      = time.time()
        log.info(
            "📦  New candidate: height=%d txs=%d subsidy=%.4f VITO fees=%d sat bits=%08x",
            height, len(txs), subsidy / COIN,
            self._estimate_fees(pending), bits,
        )

    def should_refresh(self, block: Block) -> bool:
        """True if the candidate block is outdated."""
        tip = self.chain.tip
        if tip and block.header.prev_hash != tip.hash:
            return True
        if time.time() - self._candidate_time > CANDIDATE_REFRESH:
            return True
        return False

    def increment_extra_nonce(self):
        with self._candidate_lock:
            self.extra_nonce += 1
            self._build_candidate()

    # ── Block found callback ───────────────────────────────────────────

    def on_block_found(self, block: Block):
        with self._stats_lock:
            self._blocks_found += 1

        log.info(
            f"💎  BLOCK FOUND #{block.height} | hash={block.hash[:20]}… "
            f"| nonce={block.header.nonce:,} | txs={block.tx_count} "
            f"| reward={(block_subsidy(block.height)/COIN):.4f} VITO"
        )

        ok, reason = self.chain.add_block(block)
        if ok:
            with self._candidate_lock:
                self._candidate = None   # force rebuild
            if self.on_block_found_cb:
                self.on_block_found_cb(block)
        else:
            log.warning(f"Mined block rejected: {reason}")

    # ── Stats ──────────────────────────────────────────────────────────

    def _stats_loop(self):
        last_hashes = 0
        last_time   = time.time()
        while self._running:
            time.sleep(5)
            now = time.time()
            total = sum(w.hashes for w in self._workers)
            elapsed = now - last_time
            if elapsed > 0:
                instant = (total - last_hashes) / elapsed
                with self._stats_lock:
                    self._hashrate = (
                        HASHRATE_SMOOTHING * instant +
                        (1 - HASHRATE_SMOOTHING) * self._hashrate
                    )
                    self._total_hashes = total
            last_hashes = total
            last_time   = now
            log.info(f"⛏  Hashrate: {self._format_hashrate()} | height: {self.chain.height} | blocks: {self._blocks_found}")

    @staticmethod
    def _format_hashrate_val(h: float) -> str:
        if h >= 1e12: return f"{h/1e12:.2f} TH/s"
        if h >= 1e9:  return f"{h/1e9:.2f} GH/s"
        if h >= 1e6:  return f"{h/1e6:.2f} MH/s"
        if h >= 1e3:  return f"{h/1e3:.2f} KH/s"
        return f"{h:.0f} H/s"

    def _format_hashrate(self) -> str:
        return self._format_hashrate_val(self._hashrate)

    def _estimate_fees(self, txs: List[Transaction]) -> int:
        """
        Sum real fees from the mempool _fees dict.
        Falls back to 0 if a txid is not found (e.g. manually injected tx).
        Using real fees prevents coinbase over-claiming, which causes block rejection.
        """
        total = sum(self.chain.mempool._fees.get(tx.txid, 0) for tx in txs)
        log.debug("_estimate_fees: %d txs, total_fees=%d sat", len(txs), total)
        return total

    @property
    def stats(self) -> dict:
        with self._stats_lock:
            elapsed = time.time() - self._start_time if self._start_time else 1
            return {
                "mining":       self._running,
                "threads":      self.num_workers,
                "hashrate_hps": round(self._hashrate, 2),
                "hashrate_str": self._format_hashrate_val(self._hashrate),
                "total_hashes": self._total_hashes,
                "blocks_found": self._blocks_found,
                "wallet":       self.wallet,
                "uptime_s":     int(elapsed),
                "extra_nonce":  self.extra_nonce,
            }


# ═══════════════════════════════════════════════════════════════════════
#  GETBLOCKTEMPLATE (BIP-22 compatible — for pool / external miner)
# ═══════════════════════════════════════════════════════════════════════

def getblocktemplate(blockchain: Blockchain, miner_address: str) -> dict:
    """
    Return a block template for external miners / mining pools.
    Compatible with BIP-22 getblocktemplate protocol.
    """
    tip    = blockchain.tip
    height = (tip.height + 1) if tip else 1
    subsidy = block_subsidy(height)
    bits   = blockchain._next_bits()
    target = blockchain._next_bits()

    pending = blockchain.mempool.get_block_template(max_bytes=3_900_000)
    coinbase = Transaction.coinbase(miner_address, height, subsidy)

    from vitocoin.blockchain import bits_to_target
    target_hex = f"{bits_to_target(bits):064x}"

    return {
        "version":          2,
        "previousblockhash": tip.hash if tip else "0" * 64,
        "transactions": [
            {
                "data":    tx.to_dict(),
                "txid":    tx.txid,
                "fee":     1000,
                "sigops":  1,
                "weight":  tx.size * 4,
            }
            for tx in pending
        ],
        "coinbaseaux":      {"flags": ""},
        "coinbasevalue":    subsidy,
        "coinbase_txid":    coinbase.txid,
        "target":           target_hex,
        "mintime":          blockchain._median_time_past() + 1,
        "mutable":          ["time", "transactions", "prevblock"],
        "noncerange":       "00000000ffffffff",
        "sigoplimit":       80000,
        "sizelimit":        4000000,
        "weightlimit":      16000000,
        "curtime":          int(time.time()),
        "bits":             f"{bits:08x}",
        "height":           height,
        "default_witness_commitment": "",
    }
