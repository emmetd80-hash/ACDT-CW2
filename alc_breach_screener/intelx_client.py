"""
IntelX API client (async).

Responsibilities:
- Load API key from environment (configurable env var name)
- Maintain a reusable httpx.AsyncClient
- Enforce a global async rate limit (requests_per_second)
- Apply retry/backoff rules for transient failures (429/5xx and network errors)
- Provide convenience methods:
    - start_search(term) -> search_id
    - fetch_results(search_id) -> JSON
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Dict, Optional

import httpx

from .config import AppConfig, IntelXConfig
from .utils import log_kv


class AsyncRateLimiter:
    """
    Async rate limiter enforcing a minimum interval between requests globally.

    This keeps API usage under the configured requests_per_second across all tasks.
    """

    def __init__(self, requests_per_second: float) -> None:
        self.min_interval = 1.0 / max(requests_per_second, 0.0001)
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        """
        Wait until it's safe to perform the next request.

        Uses a single lock to ensure the entire program respects a shared global
        rate (rather than per-task rate limiting).
        """
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            if elapsed < self.min_interval:
                await asyncio.sleep(self.min_interval - elapsed)
            self._last = time.monotonic()


class IntelXClient:
    """
    Async client for IntelX endpoints used by this coursework.

    Notes:
    - Free tier commonly requires base_url: https://free.intelx.io
    - API key is read from an environment variable (cfg.api_key_env)
    - Logs are emitted as structured JSON via log_kv()
    """

    def __init__(self, cfg: IntelXConfig, app: AppConfig, logger: logging.Logger) -> None:
        self.cfg = cfg
        self.app = app
        self.logger = logger

        # API key must be required
        api_key = os.getenv(cfg.api_key_env, "").strip()
        if not api_key:
            raise RuntimeError(f"Missing API key. Set environment variable {cfg.api_key_env}.")

        self.headers = {
            "x-key": api_key,
            "User-Agent": app.user_agent,
            "Accept": "application/json",
        }

        self.timeout = httpx.Timeout(
            connect=cfg.timeout_connect,
            read=cfg.timeout_read,
            write=cfg.timeout_read,
            pool=cfg.timeout_read,
        )

        # Rate limiter to ensure requests per second are minimal
        self.ratelimiter = AsyncRateLimiter(cfg.requests_per_second)

        # Create client once and reuse connections
        self._client = httpx.AsyncClient(
            base_url=cfg.base_url,
            headers=self.headers,
            timeout=self.timeout,
        )

    async def aclose(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        correlation_id: str,
    ) -> httpx.Response:
        """
        Make an async HTTP request with retry/backoff handling.

        Retries occur for:
        - Transient status codes (cfg.retry_on_status), e.g. 429 or 5xx
        - Network/timeout exceptions raised by httpx

        Backoff behaviour:
        - Starts at cfg.backoff_initial_seconds
        - Doubles each retry up to cfg.backoff_max_seconds

        Parameters
        ----------
        method:
            HTTP method (GET/POST).
        path:
            Endpoint path (e.g., "/intelligent/search").
        params/json_body:
            Query params or JSON payload.
        correlation_id:
            Privacy-preserving id used to tie logs together for a single email.
        """
        url = f"{self.cfg.base_url}{path}"
        backoff = self.cfg.backoff_initial_seconds
        last_exc: Optional[Exception] = None

        for _attempt in range(1, self.cfg.max_retries + 1):
            await self.ratelimiter.wait()
            try:
                log_kv(
                    self.logger,
                    logging.INFO,
                    "http_request",
                    cid=correlation_id,
                    method=method,
                    url=url,
                )

                resp = await self._client.request(
                    method=method,
                    url=path,
                    params=params,
                    json=json_body,
                )

                # Retry on configured statuses
                if resp.status_code in self.cfg.retry_on_status:
                    retry_after = resp.headers.get("Retry-After")
                    if retry_after:
                        try:
                            sleep_s = min(float(retry_after), self.cfg.backoff_max_seconds)
                        except ValueError:
                            sleep_s = backoff
                    else:
                        sleep_s = backoff

                    log_kv(
                        self.logger,
                        logging.WARNING,
                        "http_retry_status",
                        cid=correlation_id,
                        status=resp.status_code,
                        sleep_seconds=round(sleep_s, 2),
                    )
                    await asyncio.sleep(sleep_s)
                    backoff = min(backoff * 2.0, self.cfg.backoff_max_seconds)
                    continue

                return resp

            except (
                httpx.TimeoutException,
                httpx.ConnectError,
                httpx.ReadError,
                httpx.NetworkError,
            ) as exc:
                last_exc = exc
                log_kv(
                    self.logger,
                    logging.WARNING,
                    "http_retry_exception",
                    cid=correlation_id,
                    error=type(exc).__name__,
                    sleep_seconds=round(backoff, 2),
                )
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2.0, self.cfg.backoff_max_seconds)

        raise RuntimeError(f"HTTP request failed after retries: {method} {url} ({last_exc})")

    async def start_search(self, term: str, correlation_id: str) -> str:
        """
        Start a search for a term (email) and return the IntelX search id.

        Returns
        -------
        search_id:
            A string id required for polling /intelligent/search/result.
        """
        payload = {
            "term": term,
            "buckets": self.cfg.buckets,
            "lookuplevel": self.cfg.lookuplevel,
            "maxresults": self.cfg.max_results,
            "timeout": self.cfg.search_timeout_seconds,
            "datefrom": "",
            "dateto": "",
            "sort": self.cfg.sort,
            "media": 0,
            "terminate": [],
        }

        resp = await self._request(
            "POST",
            "/intelligent/search",
            json_body=payload,
            correlation_id=correlation_id,
        )

        if resp.status_code != 200:
            raise RuntimeError(f"Search failed: HTTP {resp.status_code} {resp.text}")

        data = resp.json()
        search_id = str(data.get("id", "")).strip()
        if not search_id:
            raise RuntimeError(f"Search response missing id: {data}")
        return search_id

    async def fetch_results(
        self,
        search_id: str,
        correlation_id: str,
        limit: int,
        offset: int,
    ) -> Dict[str, Any]:
        """
        Fetch search results for a previously created search id.

        Parameters
        ----------
        search_id:
            The id returned by start_search().
        limit / offset:
            Pagination controls (this prototype fetches first page only).

        Returns
        -------
        Parsed JSON response.
        """
        resp = await self._request(
            "GET",
            "/intelligent/search/result",
            params={"id": search_id, "limit": limit, "offset": offset},
            correlation_id=correlation_id,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"Result fetch failed: HTTP {resp.status_code} {resp.text}")
        return resp.json()