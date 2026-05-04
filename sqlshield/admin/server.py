from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from aiohttp import web

from .. import pipeline

if TYPE_CHECKING:
    from ..protocol.postgres import PostgresProxy

logger = logging.getLogger(__name__)


def build_app(proxy: "PostgresProxy") -> web.Application:
    app = web.Application()
    app["proxy"] = proxy
    app.router.add_get("/health",                  _health)
    app.router.add_get("/api/v1/stats",            _stats)
    app.router.add_get("/api/v1/baselines",        _baselines)
    app.router.add_post("/api/v1/baselines/reset", _reset_baseline)
    app.router.add_post("/api/v1/mode",            _set_mode)
    return app


async def _health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


async def _stats(request: web.Request) -> web.Response:
    s = request.app["proxy"].stats
    total = max(s["total"], 1)
    return web.json_response({
        "total":      s["total"],
        "blocked":    s["blocked"],
        "allowed":    s["allowed"],
        "block_rate": round(s["blocked"] / total, 4),
    })


async def _baselines(request: web.Request) -> web.Response:
    data = pipeline.get_anomaly_engine().export_baselines()
    return web.json_response(data)


async def _reset_baseline(request: web.Request) -> web.Response:
    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(text='{"error": "invalid JSON"}')
    user = (body.get("user") or "").strip()
    if not user:
        raise web.HTTPBadRequest(text='{"error": "user field required"}')
    removed = pipeline.get_anomaly_engine().reset_baseline(user)
    return web.json_response({"user": user, "reset": removed})


async def _set_mode(request: web.Request) -> web.Response:
    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(text='{"error": "invalid JSON"}')
    mode = (body.get("mode") or "").strip()
    valid = ("enforce", "monitor", "learning")
    if mode not in valid:
        raise web.HTTPBadRequest(text=f'{{"error": "mode must be one of {valid}"}}')
    pipeline.get_aggregator().mode = mode
    return web.json_response({"mode": mode})
