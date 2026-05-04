from __future__ import annotations

import asyncio
import logging
import os

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("sqlshield")


def _load_config() -> dict:
    for name in ("sqlshield.yaml", "sqlshield.yml"):
        if os.path.exists(name):
            try:
                import yaml
                with open(name) as f:
                    return yaml.safe_load(f) or {}
            except Exception as exc:
                logger.warning("could not parse %s: %s", name, exc)
    return {}


async def _run() -> None:
    cfg       = _load_config()
    proxy_cfg = cfg.get("proxy", {})
    admin_cfg = cfg.get("admin", {})

    from .admin.server import build_app
    from .protocol.postgres import PostgresProxy

    proxy = PostgresProxy(
        listen_host  = os.environ.get("LISTEN_HOST")  or proxy_cfg.get("listen_host",  "0.0.0.0"),
        listen_port  = int(os.environ.get("PROXY_PORT")  or proxy_cfg.get("listen_port",  6432)),
        backend_host = os.environ.get("DB_HOST")      or proxy_cfg.get("backend_host", "localhost"),
        backend_port = int(os.environ.get("DB_PORT")      or proxy_cfg.get("backend_port", 5432)),
    )
    await proxy.start()

    from aiohttp import web
    admin_port = int(os.environ.get("ADMIN_PORT") or admin_cfg.get("port", 9090))
    app = build_app(proxy)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", admin_port)
    await site.start()
    logger.info("Admin API  → http://0.0.0.0:%d", admin_port)

    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await proxy.stop()
        await runner.cleanup()


def main() -> None:
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
