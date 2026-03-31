"""FastAPI web application for ElastiHone.

This is the slim entry point that mounts middleware, static files,
and all route modules. Business logic lives in the routes/ package.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from sda.web.dependencies import STATIC_DIR

from fastapi.staticfiles import StaticFiles


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        force=True,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Startup/shutdown lifecycle."""
        # Hydrate in-memory analysis store from DB
        try:
            from sda.db import load_recent_analyses
            from sda.web.dependencies import analyses
            stored = await load_recent_analyses(limit=100)
            analyses.update(stored)
            logging.getLogger("sda.web").info(
                "Hydrated %d analyses from database", len(stored),
            )
        except Exception as exc:
            logging.getLogger("sda.web").warning(
                "Failed to hydrate analyses from DB: %s", exc,
            )
        yield
        try:
            from sda.db import close_db
            await close_db()
        except Exception:
            pass

    app = FastAPI(
        title="ElastiHone",
        description="Validate detection rule efficacy & noise before deployment",
        version="0.2.0",
        lifespan=lifespan,
    )

    # ── Middleware ─────────────────────────────────────────────────────
    from starlette.middleware.cors import CORSMiddleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5180", "http://localhost:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    from sda.web.auth import AuthMiddleware, SecurityHeadersMiddleware
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(AuthMiddleware)

    # ── Static files ──────────────────────────────────────────────────
    STATIC_DIR.mkdir(exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # ── Route modules ─────────────────────────────────────────────────
    import os
    from pathlib import Path
    frontend_dir = os.environ.get("SDA_FRONTEND_DIR", "")
    use_react = bool(frontend_dir and Path(frontend_dir).is_dir())

    from sda.web.routes.analysis import router as analysis_router
    from sda.web.routes.rules import router as rules_router
    from sda.web.routes.exceptions import router as exceptions_router
    from sda.web.routes.history import router as history_router
    from sda.web.routes.settings_api import router as settings_router

    # Only include Jinja2 page routes when NOT serving React frontend
    if not use_react:
        from sda.web.routes.pages import router as pages_router
        app.include_router(pages_router)

    app.include_router(analysis_router)
    app.include_router(rules_router)
    app.include_router(exceptions_router)
    app.include_router(history_router)
    app.include_router(settings_router)

    # ── React SPA serving (production) ────────────────────────────────
    # When SDA_FRONTEND_DIR is set (Docker/OpenShift), serve the React
    # build as the primary UI. All non-API routes fall through to index.html.
    if use_react:
        from fastapi.responses import FileResponse

        # Serve React static assets (JS, CSS, images)
        app.mount(
            "/assets",
            StaticFiles(directory=str(Path(frontend_dir) / "assets")),
            name="frontend-assets",
        )

        # SPA catch-all — must be registered LAST
        @app.get("/{full_path:path}")
        async def spa_fallback(full_path: str):
            """Serve React index.html for all non-API client-side routes."""
            # Serve static file if it exists (favicon, etc.)
            file_path = Path(frontend_dir) / full_path
            if full_path and file_path.is_file():
                return FileResponse(str(file_path))
            return FileResponse(str(Path(frontend_dir) / "index.html"))

    return app
