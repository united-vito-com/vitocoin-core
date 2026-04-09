"""
VitoCoin Stratum WebSocket Proxy
Bridges browser WebSocket clients to the local Stratum TCP server (port 3333).
Listens on port 8001 (proxied via Nginx at /ws-miner).
"""
import asyncio
import logging
import websockets

logging.basicConfig(level=logging.INFO, format="%(asctime)s [stratum-proxy] %(message)s")
log = logging.getLogger(__name__)

STRATUM_HOST = "127.0.0.1"
STRATUM_PORT = 3333
WS_PORT = 8001


async def handle_browser(websocket):
    """Bridge one browser WebSocket connection to a Stratum TCP connection."""
    peer = websocket.remote_address
    log.info("Browser connected: %s", peer)
    try:
        reader, writer = await asyncio.open_connection(STRATUM_HOST, STRATUM_PORT)
        log.info("Stratum TCP connected for %s", peer)
    except OSError as e:
        log.error("Cannot connect to Stratum: %s", e)
        await websocket.close(1011, "Stratum unavailable")
        return

    async def ws_to_tcp():
        """Forward browser messages → Stratum TCP."""
        try:
            async for message in websocket:
                if isinstance(message, str):
                    message = message.encode()
                if not message.endswith(b"\n"):
                    message += b"\n"
                writer.write(message)
                await writer.drain()
        except websockets.ConnectionClosed:
            pass
        finally:
            writer.close()

    async def tcp_to_ws():
        """Forward Stratum TCP lines → browser."""
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                await websocket.send(line.decode().rstrip("\n"))
        except (websockets.ConnectionClosed, ConnectionResetError):
            pass

    done, pending = await asyncio.wait(
        [asyncio.create_task(ws_to_tcp()), asyncio.create_task(tcp_to_ws())],
        return_when=asyncio.FIRST_COMPLETED,
    )
    for task in pending:
        task.cancel()
    log.info("Browser disconnected: %s", peer)


async def main():
    async with websockets.serve(handle_browser, "0.0.0.0", WS_PORT):
        log.info("Stratum WebSocket proxy listening on ws://0.0.0.0:%d", WS_PORT)
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
