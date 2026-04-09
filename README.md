# VitoCoin Core

> A Bitcoin-compatible Proof-of-Work blockchain built for the next generation.

---

## Vision

VitoCoin is a fully independent PoW blockchain mirroring Bitcoin core consensus rules:

- SHA-256d mining — identical double-SHA-256 Proof-of-Work
- 2016-block difficulty retarget — 10-minute target block time
- 21 million coin cap — halving every 210,000 blocks
- UTXO model — full unspent-output accounting, coinbase maturity 100 blocks
- BIP-32/39/44 HD wallets — derivation path m/44'/6333'/0'/0/N
- P2PKH scripts — Bitcoin-identical locking/unlocking scripts

---

## Tech Stack

| Layer             | Technology                                                     |
|-------------------|----------------------------------------------------------------|
| Consensus & Chain | Python 3.10+, custom Bitcoin-compatible engine                 |
| Storage           | LevelDB (via plyvel), SQLite fallback                          |
| P2P Networking    | Custom TCP wire protocol, version/verack handshake, tie-breaker dedup |
| Mining            | Multi-threaded SHA-256d + Stratum TCP server (port 3333)       |
| REST API          | Built-in HTTP server (port 6333), BIP-22 getblocktemplate      |
| WebSocket Bridge  | Stratum-over-WebSocket proxy for in-browser mining             |
| Block Explorer    | Lightweight JSON summary API (port 8080, proxied at /explorer/) |
| Webhooks          | HMAC-SHA256 signed merchant payment notifications              |
| Frontend          | Zero-Knowledge web app — AES-256-GCM wallet storage            |
| Secrets           | Environment variables only — no hardcoded credentials          |

---

## Quick Start

### Prerequisites

    sudo apt-get install -y python3 python3-venv libleveldb-dev

### Install

    git clone https://github.com/united-vito-com/vitocoin-core.git
    cd vitocoin-core
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

### Run a Full Node

    export VITO_MERCHANT_MNEMONIC="your twelve word seed phrase here"
    export VITO_WEBHOOK_SECRET="your-webhook-secret"
    export VITO_STRATUM_WALLET="<YOUR_V_ADDRESS>"

    python node.py \
      --api-port 6333 \
      --p2p-port 6334 \
      --data-dir ~/.vitocoin \
      --mine \
      --wallet <YOUR_V_ADDRESS> \
      --threads 4

### Connect a Stratum Miner

    # External miner (any SHA-256 ASIC or cgminer-compatible software)
    export VITO_STRATUM_WALLET="<YOUR_V_ADDRESS>"
    python vitocoin/stratum.py
    # Point miner at: stratum+tcp://<node-ip>:3333

    # Browser miner (via WebSocket bridge)
    python vitocoin/stratum_proxy.py   # listens on port 8001
    # Nginx proxies /ws-miner → stratum_proxy → stratum.py

### REST API Reference

    GET  /status                          Node health + chain tip
    GET  /mempool                         Pending transactions
    GET  /mining/template?wallet=<addr>   BIP-22 block template
    GET  /blocks                          Recent blocks (paginated)
    GET  /block/<height|hash>             Block by height or hash
    GET  /tx/<txid>                       Transaction lookup
    POST /tx                              Broadcast raw transaction
    POST /mining/submit                   Submit mined block

### Merchant Webhook API

    POST /v1/merchants/register           Register {address, url, secret}
    GET  /v1/merchants/status/<address>   Subscriptions + payment history

Webhooks are fired for each on-chain payment to a registered address.
Payload is signed: `X-VitoCoin-Signature: sha256=<hmac-hex>`

Verify in Python:
    import hmac, hashlib
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(expected, request.headers["X-VitoCoin-Signature"])

---

## Architecture

    node.py                  entry point — wires all components
    vitocoin/
      blockchain.py          chain, UTXO set, consensus, reorg, block_listeners[]
      transaction.py         ECDSA signing, script engine, mempool
      network.py             P2P TCP, version handshake, tie-breaker dedup
      api.py                 REST HTTP, rate limiting, CSRF guard
      miner.py               SHA-256d multi-threaded miner
      stratum.py             Stratum TCP bridge (port 3333)
      stratum_proxy.py       WebSocket-to-TCP Stratum bridge (port 8001)
      explorer.py            Block Explorer JSON API (port 8080)
      webhooks.py            Merchant webhook manager (HMAC-SHA256 signed)
      crypto.py              secp256k1, BIP-39/32/44, address encoding
      store.py               LevelDB / SQLite backend abstraction
      merchant.py            Payment processing engine

---

## Security Audit (April 2026)

| ID    | Severity | Description                                                      | Status     |
|-------|----------|------------------------------------------------------------------|------------|
| SEC-1 | Critical | Admin reset endpoint with hardcoded secret removed               | ✅ Fixed    |
| SEC-2 | Critical | Merchant mnemonic moved to `VITO_MERCHANT_MNEMONIC` env var      | ✅ Fixed    |
| SEC-3 | Critical | Wallet keys AES-256-GCM encrypted; stripped from cloud sync      | ✅ Fixed    |
| F-01  | Critical | Private keys never stored in Supabase; scrub migration on login  | ✅ Fixed    |
| F-02  | High     | Zero-knowledge sync — only public data reaches cloud             | ✅ Fixed    |
| F-03  | High     | XFF only trusted from local Nginx (`TRUSTED_PROXIES`)            | ✅ Fixed    |
| F-06  | High     | CSRF Origin allowlist on `POST /tx`                              | ✅ Fixed    |
| F-07  | Medium   | Within-block double-spend guard (`spent_in_block` set)           | ✅ Fixed    |
| F-11  | Medium   | CSP + HSTS + Permissions-Policy on all Nginx API responses       | ✅ Fixed    |
| F-04  | High     | 51% risk: all nodes mine to same wallet — **open Stratum port 3333 to external miners** | ⚠️ Monitored |
| F-08  | Medium   | Eclipse/Sybil: small network (3 nodes) — add more seed nodes     | Open       |
| F-09  | Medium   | Fake hashrate self-reporting in `/status`                        | Open       |
| F-10  | Medium   | BIP-39 PBKDF2 only 2048 iterations in HD wallet derivation       | Open       |

**F-04 Note:** The 51% concentration detector logs a warning when one address
controls ≥ 50% of the last 50 blocks. To reduce risk, encourage external miners
to connect via `stratum+tcp://<node-ip>:3333`. The Stratum WebSocket bridge
allows browser-based participation via `wss://<domain>/ws-miner`.

**Zero-Knowledge Cloud Sync:** Only wallet addresses and labels sync to cloud.
Mnemonics and WIF private keys never leave the browser.
All localStorage data encrypted with AES-256-GCM + PBKDF2 (310,000 iterations).

---

## Seed Nodes

Configure your cluster in `vitocoin/network.py` under `SEED_NODES`.
Replace the default IPs with your own infrastructure before publishing.

---

## Contributing

Pull requests welcome. Run:

    python3 -m py_compile vitocoin/*.py

before submitting. Secrets must never be hardcoded — use environment variables.

---

## License

MIT © VitoCoin Contributors
