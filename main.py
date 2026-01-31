# Imports
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

import matplotlib.pyplot as plt
import requests
import yaml

# Paths
INPUT_EMAIL_CSV = os.getenv("INPUT_EMAIL_CSV")

SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = SCRIPT_DIR / "config.yml"

OUTPUT_CSV = Path(os.getenv("OUTPUT_CSV", SCRIPT_DIR / "output_result1.csv"))

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")


# Logging (structured JSON)
def setup_logger(level: str) -> logging.Logger:
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
    payload = {"msg": msg, **fields}
    logger.log(level, json.dumps(payload, ensure_ascii=False))


# Config
@dataclass(frozen=True)
class IntelXConfig:
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


@dataclass(frozen=True)
class AppConfig:
    log_level: str
    user_agent: str


def load_config(path: Path) -> Tuple[IntelXConfig, AppConfig]:
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
    )

    app_cfg = AppConfig(
        log_level=str(app.get("log_level", "INFO")),
        user_agent=str(app.get("user_agent", "ALC-Breach-Screener/1.0")),
    )

    return intelx_cfg, app_cfg


# Helpers
def is_valid_email(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email.strip()))


def correlation_id_for(email: str) -> str:
    digest = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
    return digest[:12]


def extract_source_domain(item: Dict[str, Any]) -> Optional[str]:
    """
    Tries to derive a "site/domain where breached" from IntelX record fields.
    Often the record has 'name' that may contain a URL or domain.
    """
    name = str(item.get("name", "")).strip()
    if not name:
        return None

    if name.startswith("http://") or name.startswith("https://"):
        try:
            host = urlparse(name).hostname
            return host.lower() if host else None
        except Exception:
            return None

    m = re.search(r"([A-Za-z0-9-]+\.[A-Za-z]{2,})", name)
    if m:
        return m.group(1).lower()

    return None


# NEW: Analyst summary (top sources + counts)
def build_analyst_summary(results: Sequence["ScreenResult"], *, top_n: int = 10) -> Dict[str, Any]:
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


# NEW: Summary CSV writer (for evidence)
def write_summary_csv(path: Path, summary: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "value"])
        writer.writerow(["total_emails", summary["total_emails"]])
        writer.writerow(["breached_emails", summary["breached_emails"]])
        writer.writerow(["unique_sources", summary["unique_sources"]])

        writer.writerow([])
        writer.writerow(["top_sources_domain", "count"])
        for row in summary["top_sources"]:
            writer.writerow([row["domain"], row["count"]])


# Rate limiter
class RateLimiter:
    def __init__(self, requests_per_second: float) -> None:
        self.min_interval = 1.0 / max(requests_per_second, 0.0001)
        self._last = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last = time.monotonic()


# IntelX Communication
class IntelXClient:
    def __init__(self, cfg: IntelXConfig, app: AppConfig, logger: logging.Logger) -> None:
        self.cfg = cfg
        self.app = app
        self.logger = logger

        api_key = os.getenv(cfg.api_key_env, "").strip()
        if not api_key:
            raise RuntimeError(f"Missing API key. Set environment variable {cfg.api_key_env}.")

        self.session = requests.Session()
        self.session.headers.update(
            {
                "x-key": api_key,
                "User-Agent": app.user_agent,
                "Accept": "application/json",
            }
        )
        self.ratelimiter = RateLimiter(cfg.requests_per_second)

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        correlation_id: str,
    ) -> requests.Response:
        url = f"{self.cfg.base_url}{path}"
        timeout = (self.cfg.timeout_connect, self.cfg.timeout_read)

        backoff = self.cfg.backoff_initial_seconds
        last_exc: Optional[Exception] = None

        for _attempt in range(1, self.cfg.max_retries + 1):
            self.ratelimiter.wait()
            try:
                log_kv(
                    self.logger,
                    logging.INFO,
                    "http_request",
                    cid=correlation_id,
                    method=method,
                    url=url,
                )

                resp = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json_body,
                    timeout=timeout,
                )

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
                    time.sleep(sleep_s)
                    backoff = min(backoff * 2.0, self.cfg.backoff_max_seconds)
                    continue

                return resp

            except (requests.Timeout, requests.ConnectionError) as exc:
                last_exc = exc
                log_kv(
                    self.logger,
                    logging.WARNING,
                    "http_retry_exception",
                    cid=correlation_id,
                    error=type(exc).__name__,
                    sleep_seconds=round(backoff, 2),
                )
                time.sleep(backoff)
                backoff = min(backoff * 2.0, self.cfg.backoff_max_seconds)

        raise RuntimeError(f"HTTP request failed after retries: {method} {url} ({last_exc})")

    def start_search(self, term: str, correlation_id: str) -> str:
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

        resp = self._request(
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

    def fetch_results(
        self,
        search_id: str,
        correlation_id: str,
        limit: int,
        offset: int,
    ) -> Dict[str, Any]:
        resp = self._request(
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
    email_address: str
    breached: bool
    site_where_breached: List[str]


def screen_email(client: IntelXClient, email: str, logger: logging.Logger) -> ScreenResult:
    cid = correlation_id_for(email)

    if not is_valid_email(email):
        log_kv(logger, logging.ERROR, "invalid_email", cid=cid, email=email)
        return ScreenResult(email_address=email, breached=False, site_where_breached=[])

    search_id = client.start_search(email, correlation_id=cid)
    delay = client.cfg.result_poll_initial_delay_seconds
    last_data: Dict[str, Any] = {}

    for _ in range(client.cfg.result_poll_attempts):
        time.sleep(delay)
        data = client.fetch_results(
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

    if isinstance(records, list):
        for item in records:
            if isinstance(item, dict):
                dom = extract_source_domain(item)
                if dom:
                    sources.append(dom)

    seen = set()
    uniq_sources: List[str] = []
    for s in sources:
        if s not in seen:
            seen.add(s)
            uniq_sources.append(s)

    breached = bool(records) or bool(uniq_sources)

    log_kv(
        logger,
        logging.INFO,
        "email_screened",
        cid=cid,
        breached=breached,
        sources=len(uniq_sources),
        raw_results=len(records) if isinstance(records, list) else 0,
    )

    return ScreenResult(
        email_address=email,
        breached=breached,
        site_where_breached=uniq_sources,
    )


# CSV handling
def read_emails_from_csv(path: str) -> List[str]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Input CSV not found: {path}")

    emails: List[str] = []
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f)
        header = next(reader, None)  # header required by brief
        if header is None:
            return []
        for row in reader:
            if not row:
                continue
            emails.append(row[0].strip())
    return emails


def write_results_csv(path: Path, results: Sequence[ScreenResult]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["email_address", "breached", "site_where_breached"])
        for r in results:
            writer.writerow(
                [
                    r.email_address,
                    str(bool(r.breached)),
                    ";".join(r.site_where_breached),
                ]
            )


# Chart Output
def write_breach_chart_png(
    output_path: Path,
    results: Sequence[ScreenResult],
    *,
    top_n: int = 10,
) -> None:
    counts: Dict[str, int] = {}
    for r in results:
        if not r.breached:
            continue
        for src in r.site_where_breached:
            counts[src] = counts.get(src, 0) + 1

    if not counts:
        # No breaches -> no chart
        return

    top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:top_n]
    labels = [k for k, _ in top]
    values = [v for _, v in top]

    plt.figure(figsize=(10, 5))
    plt.bar(labels, values)
    plt.title("Top breach sources/domains (count of affected emails)")
    plt.xlabel("Source / domain")
    plt.ylabel("Count")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()


# Main
def main() -> int:
    intelx_cfg, app_cfg = load_config(CONFIG_PATH)
    logger = setup_logger(app_cfg.log_level)

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
    )

    try:
        emails = read_emails_from_csv(INPUT_EMAIL_CSV)
    except Exception as exc:
        log_kv(logger, logging.ERROR, "read_input_failed", error=str(exc))
        return 2

    if not emails:
        log_kv(logger, logging.ERROR, "no_emails_found", input_csv=INPUT_EMAIL_CSV)
        return 2

    try:
        client = IntelXClient(intelx_cfg, app_cfg, logger)
    except Exception as exc:
        log_kv(logger, logging.ERROR, "client_init_failed", error=str(exc))
        return 2

    results: List[ScreenResult] = []
    for email in emails:
        try:
            results.append(screen_email(client, email, logger))
        except Exception as exc:
            cid = correlation_id_for(email)
            log_kv(logger, logging.ERROR, "screen_failed", cid=cid, email=email, error=str(exc))
            results.append(
                ScreenResult(
                    email_address=email,
                    breached=False,
                    site_where_breached=[],
                )
            )

    # NEW: log + write concise analyst summary
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
    try:
        summary_path = OUTPUT_CSV.with_name("breach_summary.csv")
        write_summary_csv(summary_path, summary)
        log_kv(logger, logging.INFO, "summary_written", summary_path=str(summary_path))
    except Exception as exc:
        log_kv(logger, logging.WARNING, "summary_write_failed", error=str(exc))

    try:
        write_results_csv(OUTPUT_CSV, results)
    except Exception as exc:
        log_kv(logger, logging.ERROR, "write_output_failed", error=str(exc))
        return 2

    # Creating chart output
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


if __name__ == "__main__":
    raise SystemExit(main())
