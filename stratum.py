"""
VitoCoin Stratum Server
=======================
Lightweight asyncio TCP server implementing the Stratum mining protocol.
Bridges external miners to the VitoCoin node API.

Endpoints used:
  GET  /mining/template?wallet=<addr>   -> block template (BIP-22)
  POST /mining/submit                   -> full block submission
"""

import asyncio
import json
import logging
import time
import aiohttp

import os
WALLET = os.environ.get("VITO_STRATUM_WALLET", "")  # set via env or --wallet arg
PORT        = 3333
NODE_URL    = "http://localhost:6333"

log = logging.getLogger("VitoCoin.stratum")


class StratumServer:
    def __init__(self, node_api_url=NODE_URL):
        self.node_api_url   = node_api_url
        self.current_job_id = 0
        self.clients        = set()
        # Store most recent job template keyed by job_id string
        self._jobs: dict    = {}

    # ── Template fetch ─────────────────────────────────────────────────

    async def fetch_block_template(self) -> dict:
        """Call the node REST API and return a BIP-22 block template."""
        if not WALLET:
            raise ValueError("VITO_STRATUM_WALLET env var not set")
        url = f"{self.node_api_url}/mining/template?wallet={WALLET}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                return await resp.json()

    # ── Job broadcast ──────────────────────────────────────────────────

    async def broadcast_new_job(self):
        """Fetch a fresh template and send mining.notify to all connected miners."""
        try:
            template = await self.fetch_block_template()
        except Exception as e:
            log.error("fetch_block_template failed: %s", e)
            return

        self.current_job_id += 1
        job_id = str(self.current_job_id)

        # Store full template so we can reconstruct the block on submit
        self._jobs[job_id] = template
        # Keep only last 4 jobs to bound memory
        if len(self._jobs) > 4:
            oldest = sorted(self._jobs.keys())[0]
            del self._jobs[oldest]

        # Stratum mining.notify params:
        # [job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs]
        job_msg = {
            "id":     None,
            "method": "mining.notify",
            "params": [
                job_id,
                template["previousblockhash"],
                "",   # coinb1 — full coinbase serialisation left for future work
                "",   # coinb2
                [t["txid"] for t in template.get("transactions", [])],
                template["version"],
                template["bits"],
                template["curtime"],
                True  # clean_jobs
            ]
        }
        payload = (json.dumps(job_msg) + "\n").encode()
        dead = set()
        for writer in list(self.clients):
            try:
                writer.write(payload)
                await writer.drain()
            except Exception:
                dead.add(writer)
        for w in dead:
            self.clients.discard(w)

    # ── Block submission ───────────────────────────────────────────────

    async def _submit_block(self, job_id: str, nonce: str, ntime: str) -> dict:
        """
        Reconstruct the full block from the stored job template and the
        miner-supplied nonce/ntime, then POST it to POST /mining/submit.
        Returns the node response dict.
        """
        template = self._jobs.get(job_id)
        if not template:
            return {"accepted": False, "reason": "unknown job_id"}

        coinbase_tx = template.get("coinbase_tx")
        if not coinbase_tx:
            return {"accepted": False, "reason": "template missing coinbase_tx"}

        # Build full transaction list: coinbase first, then mempool txs
        transactions = [coinbase_tx] + [t["data"] for t in template.get("transactions", [])]

        # Assemble the block object expected by POST /mining/submit
        block = {
            "header": {
                "version":     template["version"],
                "prev_hash":   template["previousblockhash"],
                "merkle_root": template["merkle_root"],
                "timestamp":   int(ntime, 16) if ntime.startswith("0") else int(ntime),
                "bits":        template["bits_int"],
                "nonce":       int(nonce, 16) if nonce.startswith("0") else int(nonce),
            },
            "transactions": transactions,
            "height":        template["height"],
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.node_api_url}/mining/submit",
                json=block,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                return await resp.json()

    # ── Client handler ─────────────────────────────────────────────────

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info("peername")
        log.info("New miner connected: %s", addr)
        self.clients.add(writer)

        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break

                for line in data.decode(errors="replace").strip().split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        msg    = json.loads(line)
                        method = msg.get("method")
                        mid    = msg.get("id")

                        if method == "mining.subscribe":
                            resp = {
                                "id": mid,
                                "result": [
                                    [["mining.set_difficulty", "1"],
                                     ["mining.notify", "ae6812eb439baa55"]],
                                    "extra_nonce_1",
                                    4
                                ],
                                "error": None
                            }
                            writer.write((json.dumps(resp) + "\n").encode())
                            await writer.drain()

                        elif method == "mining.authorize":
                            resp = {"id": mid, "result": True, "error": None}
                            writer.write((json.dumps(resp) + "\n").encode())
                            await writer.drain()
                            # Send first job immediately after authorization
                            await self.broadcast_new_job()

                        elif method == "mining.submit":
                            params = msg.get("params", [])
                            if len(params) < 5:
                                resp = {"id": mid, "result": False,
                                        "error": [20, "bad params", None]}
                                writer.write((json.dumps(resp) + "\n").encode())
                                await writer.drain()
                                continue

                            worker, job_id, en2, ntime, nonce = params[:5]
                            log.info("mining.submit from %s: job=%s nonce=%s ntime=%s",
                                     worker, job_id, nonce, ntime)

                            # Forward to node
                            result = await self._submit_block(job_id, nonce, ntime)
                            log.info("submit result from node: %s", result)

                            if result.get("accepted"):
                                resp = {"id": mid, "result": True, "error": None}
                                writer.write((json.dumps(resp) + "\n").encode())
                                await writer.drain()
                                # Broadcast a fresh job to all miners
                                await self.broadcast_new_job()
                            else:
                                reason = result.get("reason", "invalid block")
                                resp = {"id": mid, "result": False,
                                        "error": [20, reason, None]}
                                writer.write((json.dumps(resp) + "\n").encode())
                                await writer.drain()

                    except json.JSONDecodeError:
                        log.warning("Invalid JSON from %s: %.80s", addr, line)
                    except Exception as e:
                        log.error("Handler error for %s: %s", addr, e, exc_info=True)

        except asyncio.IncompleteReadError:
            pass
        finally:
            self.clients.discard(writer)
            writer.close()
            log.info("Miner disconnected: %s", addr)


# ── Entry point ────────────────────────────────────────────────────────

async def main():
    server = StratumServer()
    srv = await asyncio.start_server(server.handle_client, "0.0.0.0", PORT)
    addrs = ", ".join(str(s.getsockname()) for s in srv.sockets)
    print(f"Stratum Server listening on {addrs}")
    log.info("Stratum Server started on port %d", PORT)
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    asyncio.run(main())
