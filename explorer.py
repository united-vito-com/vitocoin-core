import aiohttp
from aiohttp import web

async def handle_home(request):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("http://localhost:6333/status") as resp:
                status = await resp.json()
            async with session.get("http://localhost:6333/mempool") as resp:
                mempool = await resp.json()

        return web.json_response({
            "network": "VitoCoin Mainnet",
            "height": status["height"],
            "best_hash": status["best_hash"],
            "peers": status["peers"],
            "mempool_size": len(mempool),
            "version": "2.0.1-LevelDB",
            "status": "online"
        })
    except Exception as e:
        return web.json_response({"status": "error", "message": str(e)}, status=500)

app = web.Application()
app.add_routes([web.get("/api/summary", handle_home)])

if __name__ == "__main__":
    web.run_app(app, port=8080)
