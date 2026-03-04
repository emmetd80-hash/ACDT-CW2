"""
Configuration and constants for ALC Breach Screener.

This module provides:
- Strongly-typed configuration models (IntelXConfig, AppConfig)
- YAML config loader (load_config)
- Common constants used across modules (EMAIL_REGEX, MEDIA_TYPE_MAP)

Secrets note:
- The IntelX API key is NEVER stored in config.yml.
- config.yml stores only the ENV VAR NAME that contains the key (api_key_env).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

import yaml

# Simple email validation regex
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")

# Media type mapping
MEDIA_TYPE_MAP = {
    24: "Text File",
    27: "Database File",
    32: "CSV File",
    33: "Email File",
    34: "Archive",
}


@dataclass(frozen=True)
class IntelXConfig:
    """
    Configuration for IntelX API access and retry behaviour.

    Loaded from config.yml under the `intelx:` section.

    Fields include:
    - base_url: IntelX API
    - api_key_env: environment variable name that holds the API key
    - requests_per_second: global request pacing across all async tasks
    - timeouts: connect/read values passed to httpx
    - retry/backoff: transient error handling for 429/5xx etc
    - result polling: attempts + initial delay for /search/result readiness
    - max_concurrency: how many emails are processed concurrently
    """

    base_url: str
    api_key_env: str
    requests_per_second: float
    timeout_connect: float
    timeout_read: float
    max_retries: int
    backoff_initial_seconds: float
    backoff_max_seconds: float
    retry_on_status: Tuple[int, ...]
    max_results: int
    search_timeout_seconds: int
    sort: int
    lookuplevel: int
    buckets: List[str]
    result_poll_attempts: int
    result_poll_initial_delay_seconds: float
    max_concurrency: int


@dataclass(frozen=True)
class AppConfig:
    """
    App-level configuration (loaded from config.yml under the `app:` section).
    """

    log_level: str
    user_agent: str


def load_config(path: Path) -> Tuple[IntelXConfig, AppConfig]:
    """
    Load IntelX and application configuration from YAML.

    Parameters
    ----------
    path:
        Path to config.yml.

    Returns
    -------
    (IntelXConfig, AppConfig)

    Raises
    ------
    FileNotFoundError:
        If config.yml does not exist at the provided path.
    KeyError:
        If expected keys/sections are missing.
    """
    if not path.exists():
        raise FileNotFoundError(f"config.yml not found at: {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    ix = raw["intelx"]
    app = raw["app"]

    intelx_cfg = IntelXConfig(
        base_url=str(ix["base_url"]).rstrip("/"),
        api_key_env=str(ix.get("api_key_env", "INTELX_API_KEY")),
        requests_per_second=float(ix.get("requests_per_second", 1.0)),
        timeout_connect=float(ix.get("timeout_connect", 5)),
        timeout_read=float(ix.get("timeout_read", 25)),
        max_retries=int(ix.get("max_retries", 5)),
        backoff_initial_seconds=float(ix.get("backoff_initial_seconds", 1.0)),
        backoff_max_seconds=float(ix.get("backoff_max_seconds", 20.0)),
        retry_on_status=tuple(int(x) for x in ix.get("retry_on_status", [429, 500, 502, 503, 504])),
        max_results=int(ix.get("max_results", 40)),
        search_timeout_seconds=int(ix.get("search_timeout_seconds", 0)),
        sort=int(ix.get("sort", 2)),
        lookuplevel=int(ix.get("lookuplevel", 0)),
        buckets=list(ix.get("buckets", [])),
        result_poll_attempts=int(ix.get("result_poll_attempts", 6)),
        result_poll_initial_delay_seconds=float(ix.get("result_poll_initial_delay_seconds", 0.5)),
        max_concurrency=int(ix.get("max_concurrency", 5)),
    )

    app_cfg = AppConfig(
        log_level=str(app.get("log_level", "INFO")),
        user_agent=str(app.get("user_agent", "ALC-Breach-Screener/1.0")),
    )

    return intelx_cfg, app_cfg
