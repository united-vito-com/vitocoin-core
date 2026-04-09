"""
VitoCoin ChainStore — Persistent Storage Abstraction
============================================================
Provides a unified key-value interface over LevelDB (primary) with
automatic SQLite fallback if plyvel is unavailable.

Key families:
  b:<hash>        → BlockHeader (JSON bytes)          block header index
  B:<height_8be>  → block_hash (64 bytes)             height → hash index
  T:<hash>        → block body (JSON bytes, full txs) block body store
  u:<txid>:<idx>  → UTXO entry (JSON bytes)           UTXO set
  U:<height_8be>  → undo-diff (JSON bytes)            undo data for reorg
  x:<txid>        → tx location (JSON bytes)          tx index: {h, i}
  m:<key>         → chain metadata (UTF-8 bytes)      tip, height, etc.

Design rules:
  • All keys are bytes, all values are bytes.
  • JSON is used for values to keep ser/deser simple and human-readable.
  • Height keys use 8-byte big-endian encoding so lexicographic order =
    numeric order (enables range scans and prefix iteration).
  • The Store is NOT thread-safe on its own — the Blockchain._lock
    serialises all writes from above.
"""

import json
import logging
import os
import struct
import threading
from typing import Iterator, Optional, Tuple

log = logging.getLogger("VitoCoin.store")

# ── Backend selection ──────────────────────────────────────────────────

try:
    import plyvel
    _PLYVEL_AVAILABLE = True
    log.info("ChainStore: LevelDB backend (plyvel) selected")
except ImportError:
    _PLYVEL_AVAILABLE = False
    log.warning("ChainStore: plyvel not available — falling back to SQLite backend")


# ── Key helpers ────────────────────────────────────────────────────────

def _h8(height: int) -> bytes:
    """Encode a block height as 8-byte big-endian for lexicographic ordering."""
    return struct.pack(">Q", height)


def key_block_header(block_hash: str) -> bytes:
    return b"b:" + block_hash.encode()

def key_block_height(height: int) -> bytes:
    return b"B:" + _h8(height)

def key_block_body(block_hash: str) -> bytes:
    return b"T:" + block_hash.encode()

def key_utxo(txid: str, index: int) -> bytes:
    return f"u:{txid}:{index}".encode()

def key_undo(height: int) -> bytes:
    return b"U:" + _h8(height)

def key_tx_index(txid: str) -> bytes:
    return b"x:" + txid.encode()

def key_meta(name: str) -> bytes:
    return b"m:" + name.encode()


# ═══════════════════════════════════════════════════════════════════════
#  BASE INTERFACE
# ═══════════════════════════════════════════════════════════════════════

class ChainStore:
    """
    Abstract key-value store interface.
    Concrete backends: LevelDBStore, SQLiteStore.
    """

    def put(self, key: bytes, value: bytes) -> None:
        raise NotImplementedError

    def get(self, key: bytes) -> Optional[bytes]:
        raise NotImplementedError

    def delete(self, key: bytes) -> None:
        raise NotImplementedError

    def write_batch(self, pairs: list, deletes: list = None) -> None:
        """Atomic multi-write. pairs = [(key, value), ...], deletes = [key, ...]"""
        raise NotImplementedError

    def iter_prefix(self, prefix: bytes) -> Iterator[Tuple[bytes, bytes]]:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError

    # ── High-level typed helpers ────────────────────────────────────────

    def put_json(self, key: bytes, obj) -> None:
        self.put(key, json.dumps(obj, separators=(",", ":")).encode())

    def get_json(self, key: bytes):
        raw = self.get(key)
        return json.loads(raw) if raw is not None else None

    def put_str(self, key: bytes, s: str) -> None:
        self.put(key, s.encode())

    def get_str(self, key: bytes) -> Optional[str]:
        raw = self.get(key)
        return raw.decode() if raw is not None else None

    def put_meta(self, name: str, value: str) -> None:
        self.put_str(key_meta(name), value)

    def get_meta(self, name: str) -> Optional[str]:
        return self.get_str(key_meta(name))


# ═══════════════════════════════════════════════════════════════════════
#  LEVELDB BACKEND
# ═══════════════════════════════════════════════════════════════════════

class LevelDBStore(ChainStore):
    """Primary storage backend — LevelDB via plyvel."""

    def __init__(self, path: str):
        os.makedirs(path, exist_ok=True)
        self._db = plyvel.DB(path, create_if_missing=True,
                             write_buffer_size=64 * 1024 * 1024,   # 64 MB write buffer
                             bloom_filter_bits=10)
        log.info("LevelDBStore opened: %s", path)

    def put(self, key: bytes, value: bytes) -> None:
        self._db.put(key, value)

    def get(self, key: bytes) -> Optional[bytes]:
        return self._db.get(key)

    def delete(self, key: bytes) -> None:
        self._db.delete(key)

    def write_batch(self, pairs: list, deletes: list = None) -> None:
        with self._db.write_batch(sync=True) as wb:
            for k, v in pairs:
                wb.put(k, v)
            for k in (deletes or []):
                wb.delete(k)

    def iter_prefix(self, prefix: bytes) -> Iterator[Tuple[bytes, bytes]]:
        with self._db.iterator(prefix=prefix) as it:
            for k, v in it:
                yield k, v

    def close(self) -> None:
        self._db.close()
        log.info("LevelDBStore closed")


# ═══════════════════════════════════════════════════════════════════════
#  SQLITE FALLBACK BACKEND
# ═══════════════════════════════════════════════════════════════════════

class SQLiteStore(ChainStore):
    """
    Fallback storage backend — SQLite via stdlib sqlite3.
    Schema: single table kv(key BLOB PRIMARY KEY, value BLOB).
    Key-value semantics match LevelDB for seamless substitution.
    Schema is key-value oriented so migration to LevelDB is trivial.
    """

    def __init__(self, path: str):
        import sqlite3
        os.makedirs(path, exist_ok=True)
        db_file = os.path.join(path, "chainstore.db")
        self._conn = sqlite3.connect(db_file, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS kv (key BLOB PRIMARY KEY, value BLOB) WITHOUT ROWID"
        )
        self._conn.commit()
        self._lock = threading.Lock()
        log.info("SQLiteStore opened: %s", db_file)

    def put(self, key: bytes, value: bytes) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO kv(key, value) VALUES (?, ?)", (key, value)
            )
            self._conn.commit()

    def get(self, key: bytes) -> Optional[bytes]:
        with self._lock:
            cur = self._conn.execute("SELECT value FROM kv WHERE key = ?", (key,))
            row = cur.fetchone()
            return row[0] if row else None

    def delete(self, key: bytes) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM kv WHERE key = ?", (key,))
            self._conn.commit()

    def write_batch(self, pairs: list, deletes: list = None) -> None:
        with self._lock:
            for k, v in pairs:
                self._conn.execute(
                    "INSERT OR REPLACE INTO kv(key, value) VALUES (?, ?)", (k, v)
                )
            for k in (deletes or []):
                self._conn.execute("DELETE FROM kv WHERE key = ?", (k,))
            self._conn.commit()

    def iter_prefix(self, prefix: bytes) -> Iterator[Tuple[bytes, bytes]]:
        # SQLite range scan: key >= prefix AND key < prefix_next
        prefix_end = prefix[:-1] + bytes([prefix[-1] + 1]) if prefix else b"\xff" * 8
        with self._lock:
            cur = self._conn.execute(
                "SELECT key, value FROM kv WHERE key >= ? AND key < ? ORDER BY key",
                (prefix, prefix_end),
            )
            rows = cur.fetchall()
        for k, v in rows:
            yield bytes(k), bytes(v)

    def close(self) -> None:
        self._conn.close()
        log.info("SQLiteStore closed")


# ═══════════════════════════════════════════════════════════════════════
#  FACTORY
# ═══════════════════════════════════════════════════════════════════════

def open_store(data_dir: str) -> ChainStore:
    """
    Open the appropriate store for the given data directory.
    Tries LevelDB first; falls back to SQLite if plyvel is unavailable.
    """
    if _PLYVEL_AVAILABLE:
        ldb_path = os.path.join(data_dir, "chainstate")
        return LevelDBStore(ldb_path)
    else:
        return SQLiteStore(data_dir)
