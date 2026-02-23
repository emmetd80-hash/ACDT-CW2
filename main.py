"""
ALC Breach Screener (Async)

This script reads a CSV of email addresses and checks each one against the
Intelligence X (IntelX) API to determine whether it appears in known breach/leak
records. It outputs:
  - Results CSV (per email)
  - Concise analyst summary CSV (top breach sources + counts)
  - Bar chart of top breach sources

Environment variables:
  - INPUT_EMAIL_CSV: Path to the input CSV file containing email addresses.
  - INTELX_API_KEY (or whatever config.yml sets via api_key_env): IntelX API key.
  - OUTPUT_CSV: Optional path for detailed results CSV (default: output_result1.csv next to script)

Async notes:
  - Uses httpx.AsyncClient for non-blocking HTTP calls
  - Uses asyncio for polling + backoff + concurrency
  - Asunc rate limiter to ensure requests per second stay within the configured limit
"""

# Library Imports
import asyncio
import csv
import hashlib
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

import httpx
import matplotlib.pyplot as plt
import yaml

# Paths
INPUT_EMAIL_CSV = os.getenv("INPUT_EMAIL_CSV")

SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = SCRIPT_DIR / "config.yml"

OUTPUT_CSV = Path(os.getenv("OUTPUT_CSV", str(SCRIPT_DIR / "output_result1.csv")))

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


# Logging (structured JSON)
def setup_logger(level: str) -> logging.Logger:
    """
    Configure and return a logger that emits newline-delimited log lines.

    Notes:
        - Output is written to stdout so it can be captured by CI/containers.
        - We keep a simple text prefix (timestamp + level), but the message is
          JSON produced by `log_kv()`.
        - Existing handlers are cleared to avoid duplicate logs if reconfigured.
    """
    logger = logging.getLogger("alc_breach_screener")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        fmt="%(asctime)sZ %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def log_kv(logger: logging.Logger, level: int, msg: str, **fields: Any) -> None:
    """
    Log a structured JSON message.

    Output format
    -------------
    A single line JSON object:
      {"msg":"startup","timestamp":"...","input_csv":"..."}
    """
    payload = {"msg": msg, **fields}
    logger.log(level, json.dumps(payload, ensure_ascii=False))


# Config models + loader
@dataclass(frozen=True)
class IntelXConfig:
    """
    Configuration for IntelX API access and retry behaviour.

    Fields are loaded from config.yml (intelx section).
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

    # Async concurrency controls
    max_concurrency: int  # number of emails processed at once


@dataclass(frozen=True)
class AppConfig:
    """
    App-level configuration (loaded from config.yml).
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


# Helper functions
def is_valid_email(email: str) -> bool:
    """Validate that a string email is an email address"""
    return bool(EMAIL_REGEX.match(email.strip()))


def correlation_id_for(email: str) -> str:
    """Generate a privacy-preserving correlation id for logging."""
    digest = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
    return digest[:12]


def extract_source_domain(item: Dict[str, Any]) -> Optional[str]:
    """
    Attempt to extract a source domain from an IntelX record item.
    """
    name = str(item.get("name", "")).strip()

    if not name:
        return None

    # URL handling
    if name.startswith("http://") or name.startswith("https://"):
        try:
            host = urlparse(name).hostname
            if host:
                return host.lower()
        except Exception:
            pass

        # Important: if URL has no hostname → explicitly fail
        return None

    # Domain token extraction from text
    m = re.search(r"([A-Za-z0-9-]+\.[A-Za-z]{2,})", name)
    if m:
        return m.group(1).lower()

    return None


# Analyst summary (top sources + counts)
def build_analyst_summary(results: Sequence["ScreenResult"], *, top_n: int = 10) -> Dict[str, Any]:
    """
    Produce a small, analyst-friendly summary from the full results list.

    Metrics included:
    - total_emails: number of inputs processed
    - breached_emails: number flagged as breached
    - unique_sources: how many unique source domains were observed
    - top_sources: top N domains with counts (count = number of affected emails)
    """
    total = len(results)
    breached_count = sum(1 for r in results if r.breached)

    counts: Dict[str, int] = {}
    for r in results:
        if not r.breached:
            continue
        for src in r.site_where_breached:
            if not src:
                continue
            counts[src] = counts.get(src, 0) + 1

    top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:top_n]

    return {
        "total_emails": total,
        "breached_emails": breached_count,
        "unique_sources": len(counts),
        "top_sources": [{"domain": d, "count": c} for d, c in top],
    }


def write_summary_csv(path: Path, summary: Dict[str, Any]) -> None:
    """
    Write an analyst-friendly summary CSV to disk.

    Format:
    - Key metrics first (metric, value)
    - Blank row
    - Top sources table (domain, count)
    """
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "value"])
        writer.writerow(["total_emails", summary["total_emails"]])
        writer.writerow(["breached_emails", summary["breached_emails"]])
        writer.writerow(["unique_sources", summary["unique_sources"]])

        writer.writerow([])
        writer.writerow(["top_breached_sources", "count"])
        for row in summary["top_sources"]:
            writer.writerow([row["domain"], row["count"]])


# Async rate limiter
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
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            if elapsed < self.min_interval:
                await asyncio.sleep(self.min_interval - elapsed)
            self._last = time.monotonic()


# IntelX Communication (Async)
class IntelXClient:
    """
    Async client responsibilities:
      - Load API key from environment (configurable env var name)
      - Maintain an httpx.AsyncClient with required headers
      - Apply global async rate limiting
      - Apply retry/backoff rules for transient failures
      - Provide convenience methods:
          - start_search(term) -> search_id
          - fetch_results(search_id) -> JSON
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
            base_url=cfg.base_url, headers=self.headers, timeout=self.timeout
        )

    async def aclose(self) -> None:
        """
        Close the underlying HTTP client.
        """
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
                    method=method, url=path, params=params, json=json_body
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

        Parameters
        ----------
        term:
            The search term (email address).
        correlation_id:
            Log correlation id used to link request/response logs.

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
            Pagination controls; you currently fetch only the first page.

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


# Screening logic
@dataclass
class ScreenResult:
    """
    Result of screening a single email address.

    Fields
    ------
    email_address:
        The original email string from the input CSV.
    breached:
        True if any records/sources were found; otherwise False.
    site_where_breached:
        De-duplicated list of extracted source domains for analyst reporting.
    """

    email_address: str
    breached: bool
    site_where_breached: List[str]
    media_summary: str


async def screen_email(client, email: str, logger: logging.Logger) -> ScreenResult:
    """
    Screen a single email address against IntelX.

    Steps
    -----
    1) Validate email format early (avoid wasted API calls).
    2) Start IntelX search -> returns a search id.
    3) Poll for results (records may not be ready immediately).
       - Delay starts small and doubles each attempt up to backoff_max_seconds.
    4) Extract source domains from returned record items.
    5) Return a ScreenResult with breached flag + unique sources list.
    """
    cid = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()[:12]

    if not EMAIL_REGEX.match(email.strip()):
        logger.error("invalid_email")
        return ScreenResult(email, False, [], "")

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

    # Count media file types
    media_counts: Dict[str, int] = {}

    if isinstance(records, list):
        for item in records:
            if isinstance(item, dict):
                dom = None
                name = str(item.get("name", "")).strip()
                if name.startswith("http://") or name.startswith("https://"):
                    try:
                        dom = urlparse(name).hostname
                        if dom:
                            dom = dom.lower()
                    except Exception:
                        dom = None
                else:
                    m = re.search(r"([A-Za-z0-9-]+\.[A-Za-z]{2,})", name)
                    if m:
                        dom = m.group(1).lower()

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


# CSV handling
def read_emails_from_csv(path: str) -> List[str]:
    """
    Read email addresses from a CSV file.

    Expected format
    ---------------
    - First row is a header (skipped).
    - Email addresses are in the first column.
    - Empty rows are ignored.
    """
    if not path or not os.path.exists(path):
        raise FileNotFoundError(f"Input CSV not found: {path}")

    emails: List[str] = []
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if header is None:
            return []
        for row in reader:
            if not row:
                continue
            emails.append(row[0].strip())
    return emails


# CSV handling
def write_results_csv(path: Path, results: Sequence[ScreenResult]) -> None:
    """
    Write detailed per-email results to a CSV file.

    Columns
    -------
    email_address:
        Original input email
    breached:
        True/False
    breached_sources:
        Semicolon-separated list of source domains (may be empty)
    """
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["email_address", "breached", "breach_media_summary", "breached_sources"])
        for r in results:
            writer.writerow(
                [
                    r.email_address,
                    str(bool(r.breached)),
                    r.media_summary,
                    ";".join(r.site_where_breached),
                ]
            )


def write_breach_chart_png(
    output_path: Path, results: Sequence[ScreenResult], *, top_n: int = 6
) -> None:
    """
    Generate an executive-style breach summary donut chart PNG.

    Features
    --------
    - Shows distribution of top breach sources
    - Displays percentage breakdowns
    - Includes total breach exposure metrics
    - Adds generation timestamp
    """

    # Count breach source occurrences
    counts: Dict[str, int] = {}
    total_breached = 0

    for r in results:
        if not r.breached:
            continue

        total_breached += 1

        for src in r.site_where_breached:
            counts[src] = counts.get(src, 0) + 1

    # Avoid producing an empty chart file.
    if not counts:
        return

    # Select top sources
    top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:top_n]

    labels = [k for k, _ in top]
    values = [v for _, v in top]

    # Exposure percentage inside chart
    exposure_rate = (total_breached / max(len(results), 1)) * 100

    fig, ax = plt.subplots(figsize=(7, 7))

    wedges, texts, autotexts = ax.pie(
        values,
        labels=None,
        autopct=lambda pct: f"{pct:.1f}%",
        pctdistance=0.75,
        wedgeprops=dict(width=0.4),
        startangle=90,
    )

    # Legend for source mapping
    ax.legend(
        wedges,
        labels,
        title="Top Breach Sources",
        loc="center left",
        bbox_to_anchor=(1, 0, 0.5, 1),
    )

    # Center summary statistics
    center_text = (
        f"Total Emails: {len(results)}\n"
        f"Breached: {total_breached}\n"
        f"Exposure Rate: {exposure_rate:.1f}%"
    )

    ax.text(
        0,
        0,
        center_text,
        ha="center",
        va="center",
        fontsize=10,
        fontweight="bold",
    )

    # Chart title + timestamp footer
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    ax.set_title("Breach Source Distribution", pad=20)
    plt.figtext(
        0.5,
        0.02,
        f"Generated: {timestamp}",
        ha="center",
        fontsize=8,
        style="italic",
    )

    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()


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
    intelx_cfg, app_cfg = load_config(CONFIG_PATH)
    logger = setup_logger(app_cfg.log_level)

    # Startup log
    log_kv(
        logger,
        logging.INFO,
        "startup",
        timestamp=datetime.now(timezone.utc).isoformat(),
        input_csv=INPUT_EMAIL_CSV,
        config_path=str(CONFIG_PATH),
        output_csv=str(OUTPUT_CSV),
        base_url=intelx_cfg.base_url,
        rps=intelx_cfg.requests_per_second,
        max_results=intelx_cfg.max_results,
        max_concurrency=intelx_cfg.max_concurrency,
    )

    # Read input emails. Fail early if CSV missing/invalid.
    try:
        emails = read_emails_from_csv(INPUT_EMAIL_CSV)
    except Exception as exc:
        log_kv(logger, logging.ERROR, "read_input_failed", error=str(exc))
        return 2

    if not emails:
        log_kv(logger, logging.ERROR, "no_emails_found", input_csv=INPUT_EMAIL_CSV)
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
                return ScreenResult(email_address=email, breached=False, site_where_breached=[])

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
        summary_path = OUTPUT_CSV.with_name("breach_summary.csv")
        write_summary_csv(summary_path, summary)
        log_kv(logger, logging.INFO, "summary_written", summary_path=str(summary_path))
    except Exception as exc:
        log_kv(logger, logging.WARNING, "summary_write_failed", error=str(exc))

    # Write results CSV
    try:
        write_results_csv(OUTPUT_CSV, results)
    except Exception as exc:
        log_kv(logger, logging.ERROR, "write_output_failed", error=str(exc))
        return 2

    # Create chart PNG output (skips if no records returned)
    chart_path = OUTPUT_CSV.with_name("breach_summary.png")
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
    """
    Sync wrapper for the async entrypoint.
    """
    try:
        return asyncio.run(run_async())
    except KeyboardInterrupt:
        return 2


if __name__ == "__main__":
    sys.exit(main())
