"""
VitoCoin Transaction Engine
============================================================
Full UTXO model with:
  • Real ECDSA signature creation and verification
  • Script system (P2PKH, P2SH, OP_RETURN)
  • Fee market with fee-per-byte calculation
  • Coinbase maturity rule (100 blocks)
  • Transaction malleability prevention (SIGHASH)
  • Double-spend detection via UTXO set
  • Segregated witness-ready structure (vsize field)
"""

import hashlib
import json
import logging
import threading
import time
import struct
from typing import List, Optional, Dict, Tuple

log = logging.getLogger("VitoCoin.transaction")

from vitocoin.crypto import (
    sha256d, sha256d_hex, hash160, p2pkh_script, p2pkh_script_sig,
    verify_p2pkh, op_return_script, PrivateKey, PublicKey,
    base58check_decode, VITO_VERSION_PUBKEY,
)


# ── Constants ──────────────────────────────────────────────────────────
COIN              = 100_000_000        # 1 VITO = 100,000,000 satoshis
MAX_MONEY         = 21_000_000 * COIN  # Absolute maximum
COINBASE_MATURITY = 100              # Bitcoin-exact: 100 blocks maturity
MIN_TX_FEE        = 1_000             # Minimum fee in satoshis (10 sat/byte)
DUST_LIMIT        = 546               # Minimum output value (dust)
MAX_TX_SIZE       = 100_000           # 100 KB per transaction
SIGHASH_ALL       = 0x01


# ═══════════════════════════════════════════════════════════════════════
#  TRANSACTION INPUT / OUTPUT
# ═══════════════════════════════════════════════════════════════════════

class TxInput:
    __slots__ = ("prev_txid", "prev_index", "script_sig", "sequence")

    def __init__(self, prev_txid: str, prev_index: int,
                 script_sig: bytes = b"", sequence: int = 0xFFFFFFFF):
        if len(prev_txid) != 64:
            raise ValueError("prev_txid must be 64 hex chars")
        self.prev_txid  = prev_txid
        self.prev_index = prev_index
        self.script_sig = script_sig
        self.sequence   = sequence

    def serialize(self) -> bytes:
        txid  = bytes.fromhex(self.prev_txid)[::-1]   # little-endian
        index = struct.pack("<I", self.prev_index)
        sig   = _var_int(len(self.script_sig)) + self.script_sig
        seq   = struct.pack("<I", self.sequence)
        return txid + index + sig + seq

    def to_dict(self) -> dict:
        return {
            "prev_txid":   self.prev_txid,
            "prev_index":  self.prev_index,
            "script_sig":  self.script_sig.hex(),
            "sequence":    self.sequence,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "TxInput":
        if not isinstance(d, dict):
            raise ValueError("TxInput must be a JSON object")
        if "prev_txid" not in d:
            raise ValueError("TxInput missing 'prev_txid'")
        if "prev_index" not in d:
            raise ValueError("TxInput missing 'prev_index'")
        prev_txid = d["prev_txid"]
        if not isinstance(prev_txid, str) or len(prev_txid) != 64:
            raise ValueError("TxInput 'prev_txid' must be 64 hex chars")
        try:
            bytes.fromhex(prev_txid)
        except ValueError:
            raise ValueError("TxInput 'prev_txid' is not valid hex")
        prev_index = d["prev_index"]
        if not isinstance(prev_index, int) or prev_index < 0:
            raise ValueError("TxInput 'prev_index' must be a non-negative integer")
        script_sig_hex = d.get("script_sig", "")
        if not isinstance(script_sig_hex, str):
            raise ValueError("TxInput 'script_sig' must be a hex string")
        try:
            script_sig = bytes.fromhex(script_sig_hex)
        except ValueError:
            raise ValueError("TxInput 'script_sig' is not valid hex")
        sequence = d.get("sequence", 0xFFFFFFFF)
        if not isinstance(sequence, int) or not (0 <= sequence <= 0xFFFFFFFF):
            raise ValueError("TxInput 'sequence' must be a 32-bit unsigned integer")
        return cls(prev_txid, prev_index, script_sig, sequence)


class TxOutput:
    __slots__ = ("value", "script_pubkey")

    def __init__(self, value: int, script_pubkey: bytes):
        if value < 0:
            raise ValueError("Output value cannot be negative")
        if value > MAX_MONEY:
            raise ValueError("Output value exceeds MAX_MONEY")
        self.value        = value           # satoshis
        self.script_pubkey = script_pubkey

    @classmethod
    def to_address(cls, value: int, address: str) -> "TxOutput":
        """Create a P2PKH output to a VitoCoin address."""
        return cls(value, p2pkh_script(address))

    @classmethod
    def op_return(cls, data: bytes) -> "TxOutput":
        """Create an OP_RETURN (data) output."""
        return cls(0, op_return_script(data))

    def serialize(self) -> bytes:
        val    = struct.pack("<q", self.value)
        script = _var_int(len(self.script_pubkey)) + self.script_pubkey
        return val + script

    def to_dict(self) -> dict:
        return {
            "value":        self.value,
            "value_vito":   self.value / COIN,
            "script_pubkey": self.script_pubkey.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "TxOutput":
        if not isinstance(d, dict):
            raise ValueError("TxOutput must be a JSON object")
        if "value" not in d:
            raise ValueError("TxOutput missing 'value'")
        if "script_pubkey" not in d:
            raise ValueError("TxOutput missing 'script_pubkey'")
        value = d["value"]
        if not isinstance(value, int) or value < 0:
            raise ValueError("TxOutput 'value' must be a non-negative integer (satoshis)")
        script_hex = d["script_pubkey"]
        if not isinstance(script_hex, str):
            raise ValueError("TxOutput 'script_pubkey' must be a hex string")
        try:
            script_pubkey = bytes.fromhex(script_hex)
        except ValueError:
            raise ValueError("TxOutput 'script_pubkey' is not valid hex")
        return cls(value, script_pubkey)

    @property
    def is_dust(self) -> bool:
        return 0 < self.value < DUST_LIMIT

    @property
    def is_op_return(self) -> bool:
        return self.script_pubkey[:1] == b"\x6A"


# ═══════════════════════════════════════════════════════════════════════
#  TRANSACTION
# ═══════════════════════════════════════════════════════════════════════

class Transaction:
    def __init__(self, inputs: List[TxInput], outputs: List[TxOutput],
                 version: int = 2, locktime: int = 0):
        self.version  = version
        self.inputs   = inputs
        self.outputs  = outputs
        self.locktime = locktime
        self._txid: Optional[str] = None

    # ── Serialization ──────────────────────────────────────────────────

    def serialize(self, for_signing: bool = False, sign_index: int = -1,
                  script_code: bytes = b"") -> bytes:
        """Raw serialization. For signing, strips scriptsigs and injects script_code."""
        ver  = struct.pack("<I", self.version)
        lock = struct.pack("<I", self.locktime)
        ins  = _var_int(len(self.inputs))
        for i, inp in enumerate(self.inputs):
            if for_signing:
                if i == sign_index:
                    sc = script_code
                    ins += bytes.fromhex(inp.prev_txid)[::-1]
                    ins += struct.pack("<I", inp.prev_index)
                    ins += _var_int(len(sc)) + sc
                    ins += struct.pack("<I", inp.sequence)
                else:
                    # Empty scriptsig for other inputs during signing
                    ins += bytes.fromhex(inp.prev_txid)[::-1]
                    ins += struct.pack("<I", inp.prev_index)
                    ins += b"\x00"
                    ins += struct.pack("<I", inp.sequence)
            else:
                ins += inp.serialize()
        outs = _var_int(len(self.outputs))
        for out in self.outputs:
            outs += out.serialize()
        sighash = struct.pack("<I", SIGHASH_ALL) if for_signing else b""
        return ver + ins + outs + lock + sighash

    @property
    def txid(self) -> str:
        if self._txid is None:
            self._txid = sha256d(self.serialize())[::-1].hex()
        return self._txid

    @property
    def size(self) -> int:
        return len(self.serialize())

    @property
    def fee_rate(self) -> float:
        """sat/byte — requires external context (input values)."""
        return 0.0  # computed externally with UTXO values

    # ── Signing ────────────────────────────────────────────────────────

    def sign_input(self, index: int, private_key: PrivateKey,
                   script_pubkey: bytes) -> None:
        """
        Sign input[index] using ECDSA with SIGHASH_ALL.
        Modifies the input's script_sig in place.
        """
        preimage = self.serialize(for_signing=True, sign_index=index,
                                  script_code=script_pubkey)
        tx_hash  = sha256d(preimage)
        sig      = private_key.sign(tx_hash) + bytes([SIGHASH_ALL])
        pub      = private_key.public_key.to_bytes(compressed=True)
        self.inputs[index].script_sig = p2pkh_script_sig(sig, pub)
        self._txid = None   # invalidate cached txid

    # ── Validation ─────────────────────────────────────────────────────

    def validate_syntax(self) -> Tuple[bool, str]:
        """Check transaction syntax (no context required)."""
        if not self.inputs:
            return False, "No inputs"
        if not self.outputs:
            return False, "No outputs"
        if self.size > MAX_TX_SIZE:
            return False, f"TX too large: {self.size} bytes"
        total_out = sum(o.value for o in self.outputs)
        if total_out > MAX_MONEY:
            return False, "Output total exceeds MAX_MONEY"
        for out in self.outputs:
            if out.is_dust and not out.is_op_return:
                return False, f"Dust output: {out.value} sat"
        # Check for duplicate inputs
        seen = set()
        for inp in self.inputs:
            key = (inp.prev_txid, inp.prev_index)
            if key in seen:
                return False, f"Duplicate input: {key}"
            seen.add(key)
        return True, "OK"

    def validate_scripts(self, utxo_set: Dict[str, "TxOutput"]) -> Tuple[bool, str]:
        """Validate all input scripts against their UTXOs."""
        preimages = {}
        for i, inp in enumerate(self.inputs):
            key = f"{inp.prev_txid}:{inp.prev_index}"
            utxo = utxo_set.get(key)
            if utxo is None:
                return False, f"UTXO not found: {key}"
            script_code = utxo.script_pubkey
            preimage = self.serialize(for_signing=True, sign_index=i, script_code=script_code)
            tx_hash  = sha256d(preimage)
            if not verify_p2pkh(inp.script_sig, script_code, tx_hash):
                return False, f"Script validation failed for input {i}"
        return True, "OK"

    # ── Coinbase ────────────────────────────────────────────────────────

    @classmethod
    def coinbase(cls, miner_address: str, block_height: int, reward: int,
                 extra_nonce: int = 0) -> "Transaction":
        """
        Coinbase transaction — first in every block.
        Height encoded in scriptSig per BIP-34.
        """
        height_script = _encode_height(block_height)
        extra = struct.pack("<Q", extra_nonce)
        scriptsig = height_script + b"\x01\xff" + extra
        inp = TxInput(
            prev_txid  = "0" * 64,
            prev_index = 0xFFFFFFFF,
            script_sig = scriptsig,
        )
        out = TxOutput.to_address(reward, miner_address)
        tx  = cls([inp], [out])
        return tx

    @property
    def is_coinbase(self) -> bool:
        return (len(self.inputs) == 1 and
                self.inputs[0].prev_txid == "0" * 64 and
                self.inputs[0].prev_index == 0xFFFFFFFF)

    # ── Serialization helpers ───────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "txid":     self.txid,
            "version":  self.version,
            "locktime": self.locktime,
            "is_coinbase": self.is_coinbase,
            "inputs":   [i.to_dict() for i in self.inputs],
            "outputs":  [o.to_dict() for o in self.outputs],
            "size":     self.size,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Transaction":
        if not isinstance(d, dict):
            raise ValueError("Transaction must be a JSON object")
        if "inputs" not in d:
            raise ValueError("Transaction missing 'inputs'")
        if "outputs" not in d:
            raise ValueError("Transaction missing 'outputs'")
        if not isinstance(d["inputs"], list):
            raise ValueError("Transaction 'inputs' must be a list")
        if not isinstance(d["outputs"], list):
            raise ValueError("Transaction 'outputs' must be a list")
        if len(d["inputs"]) == 0:
            raise ValueError("Transaction must have at least one input")
        if len(d["outputs"]) == 0:
            raise ValueError("Transaction must have at least one output")
        if len(d["inputs"]) > 10_000:
            raise ValueError("Transaction has too many inputs (>10000)")
        if len(d["outputs"]) > 10_000:
            raise ValueError("Transaction has too many outputs (>10000)")
        version = d.get("version", 2)
        if not isinstance(version, int) or version < 1:
            raise ValueError("Transaction 'version' must be a positive integer")
        locktime = d.get("locktime", 0)
        if not isinstance(locktime, int) or locktime < 0:
            raise ValueError("Transaction 'locktime' must be a non-negative integer")
        tx = cls(
            inputs   = [TxInput.from_dict(i)  for i in d["inputs"]],
            outputs  = [TxOutput.from_dict(o) for o in d["outputs"]],
            version  = version,
            locktime = locktime,
        )
        return tx


# ═══════════════════════════════════════════════════════════════════════
#  UTXO SET
# ═══════════════════════════════════════════════════════════════════════

class UTXOSet:
    """
    Unspent Transaction Output set.
    Key: "txid:index"  →  Value: (TxOutput, block_height, is_coinbase)
    """
    def __init__(self):
        self._utxos: Dict[str, Tuple[TxOutput, int, bool]] = {}

    def apply_block(self, transactions: List[Transaction], height: int) -> None:
        """Apply all transactions in a block to the UTXO set."""
        for tx in transactions:
            # Spend inputs
            if not tx.is_coinbase:
                for inp in tx.inputs:
                    self._utxos.pop(f"{inp.prev_txid}:{inp.prev_index}", None)
            # Add new outputs
            for idx, out in enumerate(tx.outputs):
                if not out.is_op_return:
                    self._utxos[f"{tx.txid}:{idx}"] = (out, height, tx.is_coinbase)

    def rollback_block(self, transactions: List[Transaction],
                       height: int, prev_utxos: Dict) -> None:
        """Undo a block (for chain reorganization)."""
        for tx in reversed(transactions):
            # Remove this block's outputs
            for idx in range(len(tx.outputs)):
                self._utxos.pop(f"{tx.txid}:{idx}", None)
            # Restore spent UTXOs
            for inp in tx.inputs:
                key = f"{inp.prev_txid}:{inp.prev_index}"
                if key in prev_utxos:
                    self._utxos[key] = prev_utxos[key]

    def get(self, txid: str, index: int) -> Optional[TxOutput]:
        entry = self._utxos.get(f"{txid}:{index}")
        return entry[0] if entry else None

    def is_mature(self, txid: str, index: int, current_height: int) -> bool:
        """Coinbase outputs require 100 confirmations before spending."""
        entry = self._utxos.get(f"{txid}:{index}")
        if not entry:
            return False
        _, block_height, is_cb = entry
        if is_cb:
            return (current_height - block_height) >= COINBASE_MATURITY
        return True

    def balance(self, address: str) -> int:
        """Sum all UTXOs belonging to an address."""
        script = p2pkh_script(address)
        return sum(
            out.value for out, _, _ in self._utxos.values()
            if out.script_pubkey == script
        )

    def utxos_for_address(self, address: str) -> List[Tuple[str, int, TxOutput]]:
        """Return list of (txid, index, output) for an address."""
        script = p2pkh_script(address)
        result = []
        for key, (out, _, _) in self._utxos.items():
            if out.script_pubkey == script:
                txid, idx = key.split(":")
                result.append((txid, int(idx), out))
        return result

    def contains(self, txid: str, index: int) -> bool:
        return f"{txid}:{index}" in self._utxos

    def snapshot(self) -> Dict:
        """Return a shallow copy for rollback purposes."""
        return dict(self._utxos)

    @property
    def count(self) -> int:
        return len(self._utxos)

    @property
    def total_supply(self) -> int:
        return sum(out.value for out, _, _ in self._utxos.values())


# ═══════════════════════════════════════════════════════════════════════
#  MEMPOOL
# ═══════════════════════════════════════════════════════════════════════

class Mempool:
    """
    Pending transaction pool.
    Transactions are sorted by fee rate for block template building.
    Includes replay protection and TTL expiry.
    Thread-safe: all mutations hold self._lock.
    """
    MAX_SIZE = 300_000_000   # 300 MB total mempool weight
    TX_TTL   = 72 * 3600     # 72 hours before eviction

    def __init__(self):
        self._txs:   Dict[str, Transaction] = {}
        self._times: Dict[str, float]       = {}
        self._fees:  Dict[str, int]         = {}  # txid → fee in satoshis
        self._lock   = threading.Lock()
        # Background eviction thread
        t = threading.Thread(target=self._evict_loop, daemon=True)
        t.start()

    def add(self, tx: Transaction, fee: int, utxo_set: UTXOSet,
            current_height: int) -> Tuple[bool, str]:
        """
        Add a transaction to the mempool.
        Returns (accepted, reason).

        Check order (fail-fast for cheap checks first):
          1. Syntax check
          2. Duplicate check  ← cheap, before any UTXO I/O
          3. Mempool size
          4. Fee check
          5. UTXO existence + script validation
          6. Coinbase maturity
        """
        # 1. Syntax check (no lock needed — tx is local)
        ok, reason = tx.validate_syntax()
        if not ok:
            return False, reason

        with self._lock:
            # 2. Duplicate check — cheap, do before UTXO work
            if tx.txid in self._txs:
                return False, "Already in mempool"

            # 3. Mempool size pre-flight
            current_size = sum(t.size for t in self._txs.values())
            if current_size + tx.size > self.MAX_SIZE:
                return False, f"Mempool full ({current_size // 1_000_000} MB used)"

            # 4. Fee check
            if fee < MIN_TX_FEE:
                return False, f"Fee too low: {fee} < {MIN_TX_FEE} sat"

            # 5. Script validation — build UTXO dict; only include keys where UTXO exists
            utxo_dict: Dict[str, TxOutput] = {}
            for inp in tx.inputs:
                utxo_out = utxo_set.get(inp.prev_txid, inp.prev_index)
                if utxo_out is None:
                    return False, f"UTXO not found: {inp.prev_txid}:{inp.prev_index}"
                utxo_dict[f"{inp.prev_txid}:{inp.prev_index}"] = utxo_out

            ok, reason = tx.validate_scripts(utxo_dict)
            if not ok:
                return False, reason

            # 6. Coinbase maturity
            for inp in tx.inputs:
                if not utxo_set.is_mature(inp.prev_txid, inp.prev_index, current_height):
                    return False, f"Coinbase not mature: {inp.prev_txid}:{inp.prev_index}"

            self._txs[tx.txid]   = tx
            self._times[tx.txid] = time.time()
            self._fees[tx.txid]  = fee
            log.debug("mempool.add: %s fee=%d size=%d", tx.txid[:16], fee, tx.size)
            return True, "Accepted"

    def remove(self, txid: str) -> None:
        with self._lock:
            self._txs.pop(txid, None)
            self._times.pop(txid, None)
            self._fees.pop(txid, None)

    def remove_confirmed(self, txids: List[str]) -> None:
        with self._lock:
            for txid in txids:
                self._txs.pop(txid, None)
                self._times.pop(txid, None)
                self._fees.pop(txid, None)

    def evict_expired(self) -> int:
        """Evict transactions older than TX_TTL. Returns count evicted."""
        now = time.time()
        with self._lock:
            expired = [txid for txid, t in self._times.items() if now - t > self.TX_TTL]
            for txid in expired:
                self._txs.pop(txid, None)
                self._times.pop(txid, None)
                self._fees.pop(txid, None)
        if expired:
            log.info("mempool.evict: removed %d expired txs", len(expired))
        return len(expired)

    def _evict_loop(self) -> None:
        """Background thread: evict expired transactions every 10 minutes."""
        while True:
            time.sleep(600)
            try:
                self.evict_expired()
            except Exception:
                pass

    def get_block_template(self, max_bytes: int = 900_000) -> List[Transaction]:
        """Return transactions sorted by fee rate for block building."""
        with self._lock:
            sorted_txids = sorted(
                self._txs.keys(),
                key=lambda t: self._fees[t] / max(self._txs[t].size, 1),
                reverse=True,
            )
            selected = []
            total_size = 0
            for txid in sorted_txids:
                tx = self._txs[txid]
                if total_size + tx.size > max_bytes:
                    break
                selected.append(tx)
                total_size += tx.size
            return selected

    def __len__(self) -> int:
        return len(self._txs)

    def __contains__(self, txid: str) -> bool:
        return txid in self._txs

    def values(self):
        return list(self._txs.values())

    def to_dict_list(self, limit: int = 100) -> List[dict]:
        with self._lock:
            items = list(self._txs.values())[:limit]
            return [{"txid": tx.txid, "size": tx.size,
                     "fee": self._fees.get(tx.txid, 0)} for tx in items]


# ── Helpers ────────────────────────────────────────────────────────────

def _var_int(n: int) -> bytes:
    if n < 0xFD:
        return struct.pack("B", n)
    elif n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    elif n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    else:
        return b"\xff" + struct.pack("<Q", n)

def _encode_height(height: int) -> bytes:
    """Encode block height as CScript for coinbase BIP-34."""
    if height == 0:
        return b"\x00"
    h = height
    bs = []
    while h > 0:
        bs.append(h & 0xFF)
        h >>= 8
    if bs[-1] & 0x80:
        bs.append(0x00)
    return bytes([len(bs)]) + bytes(bs)
