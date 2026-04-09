# VitoCoin Core

> A Bitcoin-compatible Proof-of-Work blockchain built for the next generation.

---

## Vision

VitoCoin is a fully independent PoW blockchain mirroring Bitcoin core consensus rules:

- SHA-256d mining — identical double-SHA-256 Proof-of-Work
- 2016-block difficulty retarget — 10-minute target block time
- 21 million coin cap — halving every 210,000 blocks
- UTXO model — full unspent-output accounting, coinbase maturity 100 blocks
- BIP-32/39/44 HD wallets — derivation path m/44/6333/0/0/N
- P2PKH scripts — Bitcoin-identical locking/unlocking scripts

---

## Tech Stack

| Layer            | Technology                                            |
|------------------|-------------------------------------------------------|
| Consensus & Chain| Python 3.10+, custom Bitcoin-compatible engine        |
| Storage          | LevelDB (via plyvel), SQLite fallback                 |
| P2P Networking   | Custom TCP wire protocol, version/verack handshake    |
| Mining           | Multi-threaded SHA-256d + Stratum TCP server (port 3333) |
| REST API         | Built-in HTTP server (port 6333), BIP-22 getblocktemplate |
| Frontend         | Zero-Knowledge web app — AES-256-GCM wallet storage  |
| Secrets          | Environment variables only — no hardcoded credentials |

---

## Quick Start

### Prerequisites

    sudo apt-get install -y python3 python3-venv libleveldb-dev

### Install

    git clone https://github.com/your-org/vitocoin.git
    cd vitocoin
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

### Run a Full Node

    export VITO_MERCHANT_MNEMONIC="your twelve word seed phrase here"
    export VITO_WEBHOOK_SECRET="your-webhook-secret"

    python node.py \
      --api-port 6333 \
      --p2p-port 6334 \
      --data-dir ~/.vitocoin \
      --mine \
      --wallet <YOUR_V_ADDRESS> \
      --threads 4

### Connect a Stratum Miner

    export VITO_STRATUM_WALLET="<YOUR_V_ADDRESS>"
    python vitocoin/stratum.py
    # Point any SHA-256 miner at: stratum+tcp://<node-ip>:3333

### REST API Reference

    GET  /status                          Node health + chain tip
    GET  /mining/template?wallet=<addr>   BIP-22 block template
    GET  /blocks                          Recent blocks (paginated)
    GET  /block/<height|hash>             Block by height or hash
    GET  /tx/<txid>                       Transaction lookup
    POST /tx                              Broadcast raw transaction
    POST /mining/submit                   Submit mined block

---

## Architecture

    node.py                  entry point — wires all components
    vitocoin/
      blockchain.py          chain, UTXO set, consensus, reorg
      transaction.py         ECDSA signing, script engine, mempool
      network.py             P2P TCP, version handshake, dedup
      api.py                 REST HTTP, rate limiting, CSRF guard
      miner.py               SHA-256d multi-threaded miner
      stratum.py             Stratum TCP bridge (port 3333)
      crypto.py              secp256k1, BIP-39/32/44, address encoding
      store.py               LevelDB / SQLite backend abstraction
      merchant.py            Payment processing engine

---

## Security Audit (April 2026)

| ID    | Severity | Description                                         | Status    |
|-------|----------|-----------------------------------------------------|-----------|
| SEC-1 | Critical | Admin reset endpoint with hardcoded secret removed  | Fixed     |
| SEC-2 | Critical | Merchant mnemonic moved to VITO_MERCHANT_MNEMONIC   | Fixed     |
| SEC-3 | Critical | Wallet keys AES-256-GCM encrypted; stripped from cloud | Fixed  |
| SEC-4 | High     | XFF only trusted from local Nginx (TRUSTED_PROXIES) | Fixed     |
| SEC-5 | High     | CSRF Origin allowlist on POST /tx                   | Fixed     |
| SEC-6 | Medium   | Within-block double-spend detection added           | Fixed     |

Zero-Knowledge Cloud Sync: only wallet addresses and labels sync to cloud.
Mnemonics and WIF private keys never leave the browser.
All localStorage data encrypted with AES-256-GCM + PBKDF2 (310,000 iterations).

---

## Seed Nodes

Configure your cluster in vitocoin/network.py under SEED_NODES.
Replace the default IPs with your own infrastructure before publishing.

---

## Contributing

Pull requests welcome. Run:

    python3 -m py_compile vitocoin/*.py

before submitting. Secrets must never be hardcoded — use environment variables.

---

## License

MIT (c) VitoCoin Contributors
