"""
vitocoin/tools/reindex.py
============================================================
Chain reindex tool — rebuilds the ChainStore index from chain.json
or re-scans an existing ChainStore to repair the transaction index.

Usage:
    python -m vitocoin.tools.reindex [--data-dir ~/.vitocoin] [--network mainnet]

What it does:
  1. Opens the data directory's ChainStore.
  2. If chain.json exists, reads all blocks from it.
     Otherwise, scans the existing block store (b: prefix).
  3. Replays each block in order:
     - Writes block header + body (idempotent — overwrites if exists)
     - Rebuilds UTXO set from scratch
     - Writes UTXO entries
     - Writes tx index (x:<txid> → {h, i})
  4. Writes final chain metadata (tip_hash, chain_work, height).

This is safe to run multiple times (all writes are idempotent).
It does NOT require a running node.
"""

import argparse
import json
import logging
import os
import struct
import sys

# Allow running as a script from the repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s  %(levelname)-8s  %(message)s")
log = logging.getLogger("VitoCoin.reindex")


def reindex(data_dir: str, network: str) -> None:
    from vitocoin.store import (
        open_store,
        key_block_header, key_block_height, key_block_body,
        key_utxo, key_tx_index, key_meta, key_undo,
    )
    from vitocoin.blockchain import Block, BlockHeader
    from vitocoin.transaction import Transaction, TxOutput, UTXOSet

    data_dir = os.path.expanduser(data_dir)
    store    = open_store(data_dir)

    # ── Collect blocks ─────────────────────────────────────────────────
    chain_file = os.path.join(data_dir, "chain.json")
    if os.path.exists(chain_file):
        log.info("Reading blocks from chain.json …")
        with open(chain_file) as f:
            raw = json.load(f)
        blocks = [Block.from_dict(b) for b in raw["blocks"]]
        log.info("  %d blocks loaded from JSON", len(blocks))
    else:
        # Scan store for block bodies in height order
        log.info("Scanning block store …")
        blocks = []
        height = 0
        while True:
            hash_raw = store.get(key_block_height(height))
            if hash_raw is None:
                break
            blk_hash = hash_raw.decode()
            body_raw = store.get(key_block_body(blk_hash))
            hdr_raw  = store.get(key_block_header(blk_hash))
            if body_raw is None or hdr_raw is None:
                log.warning("Missing body/header for height %d (%s…) — stopping", height, blk_hash[:16])
                break
            body = json.loads(body_raw)
            hdr  = BlockHeader.from_dict(json.loads(hdr_raw))
            txs  = [Transaction.from_dict(t) for t in body["transactions"]]
            blk  = Block(hdr, txs, body["height"])
            blk._hash = blk_hash
            blocks.append(blk)
            height += 1
        log.info("  %d blocks found in store", len(blocks))

    if not blocks:
        log.error("No blocks found — cannot reindex")
        store.close()
        return

    # ── Replay blocks ──────────────────────────────────────────────────
    utxo       = UTXOSet()
    chain_work = 0
    total_txs  = 0

    for blk in blocks:
        # Block records
        pairs = [
            (key_block_header(blk.hash),
             json.dumps(blk.header.to_dict(), separators=(",", ":")).encode()),
            (key_block_body(blk.hash),
             json.dumps({"height": blk.height,
                         "transactions": [tx.to_dict() for tx in blk.transactions]},
                        separators=(",", ":")).encode()),
            (key_block_height(blk.height), blk.hash.encode()),
        ]

        # Tx index
        for tx_i, tx in enumerate(blk.transactions):
            pairs.append((
                key_tx_index(tx.txid),
                json.dumps({"h": blk.height, "i": tx_i},
                           separators=(",", ":")).encode(),
            ))
            total_txs += 1

        store.write_batch(pairs)
        utxo.apply_block(blk.transactions, blk.height)
        chain_work += blk.header.work

        if blk.height % 1000 == 0:
            log.info("  … height %d", blk.height)

    # ── Write full UTXO set ────────────────────────────────────────────
    log.info("Writing %d UTXO entries …", utxo.count)

    # First delete all existing UTXO entries to handle evictions
    existing_utxo_keys = [k for k, _ in store.iter_prefix(b"u:")]
    if existing_utxo_keys:
        store.write_batch([], existing_utxo_keys)

    utxo_pairs = []
    for raw_key, (out, h, is_cb) in utxo._utxos.items():
        txid, idx = raw_key.rsplit(":", 1)
        utxo_pairs.append((
            key_utxo(txid, int(idx)),
            json.dumps({"v": out.value, "s": out.script_pubkey.hex(),
                        "h": h, "cb": is_cb},
                       separators=(",", ":")).encode(),
        ))
    # Batch in chunks of 10,000 to avoid huge single write
    chunk = 10_000
    for i in range(0, len(utxo_pairs), chunk):
        store.write_batch(utxo_pairs[i:i + chunk])

    # ── Update metadata ────────────────────────────────────────────────
    tip = blocks[-1]
    store.write_batch([
        (key_meta("tip_hash"),   tip.hash.encode()),
        (key_meta("chain_work"), str(chain_work).encode()),
        (key_meta("network"),    network.encode()),
        (key_meta("height"),     str(tip.height).encode()),
    ])

    store.close()
    log.info("Reindex complete: height=%d, txs=%d, utxos=%d",
             tip.height, total_txs, utxo.count)


def main():
    parser = argparse.ArgumentParser(description="VitoCoin chain reindex tool")
    parser.add_argument("--data-dir", default="~/.vitocoin",
                        help="Chain data directory (default: ~/.vitocoin)")
    parser.add_argument("--network", default="mainnet",
                        choices=["mainnet", "testnet"],
                        help="Network (default: mainnet)")
    args = parser.parse_args()
    reindex(args.data_dir, args.network)


if __name__ == "__main__":
    main()
