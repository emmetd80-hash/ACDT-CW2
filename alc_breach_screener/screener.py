"""
ALC Breach Screener (Async)

This module contains the core screening workflow.

What it does
------------
Reads a CSV of email addresses and checks each one against the Intelligence X
(IntelX) API to determine whether it appears in known breach/leak records.

Outputs
-------
- Results CSV (per email)
- Concise analyst summary CSV (top breach sources + counts)
- Bar/donut chart PNG summarising breach sources

Environment variables
---------------------
- INPUT_EMAIL_CSV: Path to the input CSV file containing email addresses.
- INTELX_API_KEY (or whatever config.yml sets via api_key_env): IntelX API key.
- OUTPUT_CSV: Optional path for detailed results CSV (default: output_result1.csv in CWD)

Async notes
-----------
- Uses httpx.AsyncClient for non-blocking HTTP calls
- Uses asyncio for polling + backoff + concurrency
- Uses a rate limiter to keep requests per second under the configured limit
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .config import EMAIL_REGEX, MEDIA_TYPE_MAP, load_config
from .intelx_client import IntelXClient
from .utils import (
    ScreenResult,
    build_analyst_summary,
    correlation_id_for,
    log_kv,
    read_emails_from_csv,
    setup_logger,
    write_breach_chart_png,
    write_results_csv,
    write_summary_csv,
)


def extract_source(item: Dict[str, Any]) -> Optional[str]:
    """
    Attempt to extract a useful source label from an IntelX record item.

    - If the record name is a URL, return hostname.
    - If it contains a domain-like token, return that.
    - Otherwise return cleaned record name (without [Part x of y]).
    """
    name = str(item.get("name", "")).strip()
    if not name:
        return None

    # Remove "[Part X of Y]"
    name = re.sub(r"\s*\[Part\s+\d+\s+of\s+\d+\]\s*$", "", name, flags=re.IGNORECASE)

    # URL handling
    if name.startswith(("http://", "https://")):
        try:
            host = urlparse(name).hostname
            return host.lower() if host else None
        except Exception:
            return None

    m = re.search(r"\b([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b", name)
    if m:
        return m.group(1).lower()

    return name.lower()


async def screen_email(client: IntelXClient, email: str, logger: logging.Logger) -> ScreenResult:
    """
    Screen a single email address against IntelX.

    Steps
    -----
    1) Validate email format early (avoid wasted API calls).
    2) Start IntelX search -> returns a search id.
    3) Poll for results (records may not be ready immediately).
       - Delay starts small and doubles each attempt up to backoff_max_seconds.
    4) Extract source domains + media-type summary from returned records.
    5) Return a ScreenResult with breached flag + unique sources list.
    """
    cid = correlation_id_for(email)

    if not EMAIL_REGEX.match(email.strip()):
        log_kv(logger, logging.ERROR, "invalid_email", cid=cid)
        return ScreenResult(
            email_address=email,
            breached=False,
            site_where_breached=[],
            media_summary="",
        )

    search_id = await client.start_search(email, correlation_id=cid)

    delay = client.cfg.result_poll_initial_delay_seconds
    last_data: Dict[str, Any] = {}

    for _ in range(client.cfg.result_poll_attempts):
        await asyncio.sleep(delay)

        data = await client.fetch_results(
            search_id,
            correlation_id=cid,
            limit=client.cfg.max_results,
            offset=0,
        )
        last_data = data

        records = data.get("records") or data.get("items") or []
        if isinstance(records, list) and records:
            break

        delay = min(delay * 2.0, client.cfg.backoff_max_seconds)

    records = last_data.get("records") or last_data.get("items") or []

    sources: List[str] = []
    media_counts: Dict[str, int] = {}

    if isinstance(records, list):
        for item in records:
            if not isinstance(item, dict):
                continue

            dom = extract_source(item)
            if dom:
                sources.append(dom)

            media_code = item.get("media")
            label = MEDIA_TYPE_MAP.get(media_code, f"Unknown({media_code})")
            media_counts[label] = media_counts.get(label, 0) + 1

    media_summary_str = ", ".join(
        f"{count} {label}{'s' if count > 1 else ''}"
        for label, count in sorted(media_counts.items(), key=lambda x: -x[1])
    )

    uniq_sources = list(dict.fromkeys(sources))
    breached = bool(records) or bool(uniq_sources)

    return ScreenResult(
        email_address=email,
        breached=breached,
        site_where_breached=uniq_sources,
        media_summary=media_summary_str,
    )


def _default_config_path() -> Path:
    """
    Resolve config.yml.

    Uses the current working directory so that running:
      cd <repo_root>
      python -m alc_breach_screener
    will load <repo_root>/config.yml.
    """
    return Path.cwd() / "config.yml"


async def run_async() -> int:
    """
    Async program entrypoint.

    Workflow:
      1) Load config + setup logger
      2) Read emails from input CSV
      3) Initialize IntelX async client
      4) Screen emails concurrently (bounded by max_concurrency)
      5) Build and write analyst summary CSV
      6) Write detailed results CSV
      7) Generate chart PNG (if breaches exist)
    """
    input_email_csv = os.getenv("INPUT_EMAIL_CSV")

    # All outputs go into ./output (created if missing)
    output_dir = Path.cwd() / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Allow env var override, but force it into ./output
    output_name = Path(os.getenv("OUTPUT_CSV", "output_result1.csv")).name
    output_csv = output_dir / output_name

    intelx_cfg, app_cfg = load_config(_default_config_path())
    logger = setup_logger(app_cfg.log_level)

    # Startup log
    log_kv(
        logger,
        logging.INFO,
        "startup",
        timestamp=datetime.now(timezone.utc).isoformat(),
        input_csv=input_email_csv,
        config_path=str(_default_config_path()),
        output_csv=str(output_csv),
        output_dir=str(output_dir),
        base_url=intelx_cfg.base_url,
        rps=intelx_cfg.requests_per_second,
        max_results=intelx_cfg.max_results,
        max_concurrency=intelx_cfg.max_concurrency,
    )

    # Read input emails. Fail early if CSV missing/invalid.
    try:
        emails = read_emails_from_csv(input_email_csv)
    except Exception as exc:
        log_kv(logger, logging.ERROR, "read_input_failed", error=str(exc))
        return 2

    if not emails:
        log_kv(logger, logging.ERROR, "no_emails_found", input_csv=input_email_csv)
        return 2

    # Create IntelX Client
    try:
        client = IntelXClient(intelx_cfg, app_cfg, logger)
    except Exception as exc:
        log_kv(logger, logging.ERROR, "client_init_failed", error=str(exc))
        return 2

    # Semaphore bounds the number of emails being processed concurrently
    sem = asyncio.Semaphore(max(1, intelx_cfg.max_concurrency))

    async def guarded_screen(email: str) -> ScreenResult:
        """
        Screen one email with:
        - a semaphore to bound concurrent work
        - error handling so one failure doesn't cancel the whole run
        """
        async with sem:
            try:
                return await screen_email(client, email, logger)
            except Exception as exc:
                cid = correlation_id_for(email)
                log_kv(logger, logging.ERROR, "screen_failed", cid=cid, email=email, error=str(exc))
                return ScreenResult(
                    email_address=email,
                    breached=False,
                    site_where_breached=[],
                    media_summary="",
                )

    try:
        # gather preserves order of the input list
        results = await asyncio.gather(*(guarded_screen(e) for e in emails))
    finally:
        await client.aclose()

    # Build + log + write concise analyst summary
    summary = build_analyst_summary(results, top_n=10)
    log_kv(
        logger,
        logging.INFO,
        "analyst_summary",
        total_emails=summary["total_emails"],
        breached_emails=summary["breached_emails"],
        unique_sources=summary["unique_sources"],
        top_sources=summary["top_sources"],
    )

    # Summary CSV
    try:
        summary_path = output_csv.with_name("breach_summary.csv")
        write_summary_csv(summary_path, summary)
        log_kv(logger, logging.INFO, "summary_written", summary_path=str(summary_path))
    except Exception as exc:
        log_kv(logger, logging.WARNING, "summary_write_failed", error=str(exc))

    # Write results CSV
    try:
        write_results_csv(output_csv, results)
    except Exception as exc:
        log_kv(logger, logging.ERROR, "write_output_failed", error=str(exc))
        return 2

    # Create chart PNG output (skips if no records returned)
    chart_path = output_csv.with_name("breach_summary.png")
    try:
        write_breach_chart_png(chart_path, results, top_n=10)
        if chart_path.exists():
            log_kv(logger, logging.INFO, "chart_written", chart_path=str(chart_path))
        else:
            log_kv(logger, logging.INFO, "chart_skipped_no_breaches")
    except Exception as exc:
        log_kv(logger, logging.WARNING, "chart_write_failed", error=str(exc))

    log_kv(logger, logging.INFO, "done")
    return 0


def main() -> int:
    try:
        return asyncio.run(run_async())
    except KeyboardInterrupt:
        return 2
