"""Optional API-key authentication for the v1 API.

When ``CODERISK_API_KEY`` is set in the environment / config, every request to
the v1 router must include the header ``X-API-Key: <key>``.

If the setting is empty or absent, all requests are accepted without
authentication (development / single-user mode).
"""

from __future__ import annotations

import logging
import secrets

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.core.config import Settings, get_settings

logger = logging.getLogger(__name__)

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(
    header_key: str | None = Security(_api_key_header),
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> None:
    """FastAPI dependency — validates the ``X-API-Key`` header.

    Inject with ``Depends(require_api_key)`` on a router or individual routes.
    Is a no-op when ``settings.api_key`` is unset.
    """
    configured_key = settings.api_key.get_secret_value() if settings.api_key else None

    if not configured_key:
        # Auth disabled — allow all requests
        return

    if not header_key or not secrets.compare_digest(header_key, configured_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
