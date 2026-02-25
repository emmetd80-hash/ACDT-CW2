"""
Shared utilities for ALC Breach Screener.

This module groups cross-cutting concerns:
- structured logging helpers (setup_logger, log_kv)
- privacy-preserving correlation id generation
- CSV input/output functions
- analyst summary generation + output CSV
- breach chart generation (PNG)

Note: ScreenResult lives here to avoid circular imports in the 4/5-file layout.
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Sequence

import matplotlib.pyplot as plt


@dataclass
class ScreenResult:
    """
    Result of screening a single email address.

    Fields
    ------
    email_address:
        Original input email string.
    breached:
        True if any records/sources were found; otherwise False.
    site_where_breached:
        De-duplicated list of extracted source domains (analyst reporting).
    media_summary:
        Human-readable summary of media types observed in returned records.
    """

    email_address: str
    breached: bool
    site_where_breached: List[str]
    media_summary: str


def setup_logger(level: str) -> logging.Logger:
    """
    Configure and return a logger that emits newline-delimited log lines.

    Notes:
    - Output is written to stdout so it can be captured by CI/containers.
    - We keep a simple text prefix (timestamp + level), but the message is JSON
      produced by `log_kv()`.
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

    Output format:
      {"msg":"startup","timestamp":"...","input_csv":"..."}
    """
    payload = {"msg": msg, **fields}
    logger.log(level, json.dumps(payload, ensure_ascii=False))


def correlation_id_for(email: str) -> str:
    """
    Generate a privacy-preserving correlation id for logging.

    Uses SHA-256(email_lower) and takes the first 12 hex characters.
    """
    digest = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
    return digest[:12]


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


def write_results_csv(path: Path, results: Sequence[ScreenResult]) -> None:
    """
    Write detailed per-email results to a CSV file.

    Columns
    -------
    email_address:
        Original input email
    breached:
        True/False
    breach_media_summary:
        Summary of media types returned by IntelX (optional enhancement)
    breached_sources:
        Semicolon-separated list of extracted source domains
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


def build_analyst_summary(results: Sequence[ScreenResult], *, top_n: int = 10) -> Dict[str, Any]:
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


def write_breach_chart_png(
    output_path: Path,
    results: Sequence[ScreenResult],
    *,
    top_n: int = 6,
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

    top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:top_n]
    labels = [k for k, _ in top]
    values = [v for _, v in top]

    exposure_rate = (total_breached / max(len(results), 1)) * 100

    fig, ax = plt.subplots(figsize=(7, 7))
    wedges, _texts, _autotexts = ax.pie(
        values,
        labels=None,
        autopct=lambda pct: f"{pct:.1f}%",
        pctdistance=0.75,
        wedgeprops=dict(width=0.4),
        startangle=90,
    )

    ax.legend(
        wedges,
        labels,
        title="Top Breach Sources",
        loc="center left",
        bbox_to_anchor=(1, 0, 0.5, 1),
    )

    center_text = (
        f"Total Emails: {len(results)}\n"
        f"Breached: {total_breached}\n"
        f"Exposure Rate: {exposure_rate:.1f}%"
    )
    ax.text(0, 0, center_text, ha="center", va="center", fontsize=10, fontweight="bold")

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ax.set_title("Breach Source Distribution", pad=20)
    plt.figtext(0.5, 0.02, f"Generated: {timestamp}", ha="center", fontsize=8, style="italic")

    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()
