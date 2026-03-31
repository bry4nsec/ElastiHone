"""Authentication and security middleware for ElastiHone.

Provides:
- API key authentication (SDA_API_KEY env var)
- Rate limiting via slowapi
- Security headers (CSP, X-Frame-Options, etc.)
"""

from __future__ import annotations

import logging
import os
import secrets
from typing import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# ── API Key Authentication ────────────────────────────────────────────────────

API_KEY = os.environ.get("SDA_API_KEY", "").strip()

# Paths that don't require authentication
PUBLIC_PATHS = {"/api/health", "/static", "/favicon.ico"}


class AuthMiddleware(BaseHTTPMiddleware):
    """API key authentication middleware.

    If SDA_API_KEY is set, all requests must include:
      Authorization: Bearer <key>
    or query parameter: ?api_key=<key>

    Static files, health check, and the login page are exempt.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not API_KEY:
            # No API key configured — authentication disabled
            return await call_next(request)

        path = request.url.path

        # Allow public paths
        if any(path.startswith(p) for p in PUBLIC_PATHS):
            return await call_next(request)

        # Check Authorization header
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            if secrets.compare_digest(token, API_KEY):
                return await call_next(request)

        # Check query parameter (for browser access)
        query_key = request.query_params.get("api_key", "")
        if query_key and secrets.compare_digest(query_key, API_KEY):
            return await call_next(request)

        # Check cookie (set after first successful auth)
        cookie_key = request.cookies.get("sda_auth", "")
        if cookie_key and secrets.compare_digest(cookie_key, API_KEY):
            return await call_next(request)

        logger.warning("Unauthorized access attempt from %s to %s",
                       request.client.host if request.client else "unknown", path)

        # Return 401 for API calls, redirect to login for browser requests
        if path.startswith("/api/"):
            return JSONResponse(
                status_code=401,
                content={"error": "Unauthorized", "message": "Valid API key required"},
            )

        # For browser requests, show a simple login page
        return JSONResponse(
            status_code=401,
            content={"error": "Unauthorized"},
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── Security Headers ─────────────────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Content Security Policy — allows inline styles/scripts for the report
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self' https://attack.mitre.org; "
            "frame-ancestors 'none';"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )

        return response
