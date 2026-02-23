# ruff: noqa: E402
"""
Unit tests for main.py (ALC Breach Screener).
"""

import sys
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, Mock

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import main  # noqa: I001


async def _no_sleep(_: float) -> None:
    return None


def test_read_emails_from_csv_reads_email_address_column(tmp_path: Path):
    csv_path = tmp_path / "emails.csv"
    csv_path.write_text(
        "email_address\n" "test@example.com\n" "not-an-email\n" "alice@example.org\n",
        encoding="utf-8",
    )

    emails = main.read_emails_from_csv(str(csv_path))
    assert emails == ["test@example.com", "not-an-email", "alice@example.org"]


def test_read_emails_from_csv_missing_file_raises(tmp_path: Path):
    missing = tmp_path / "missing.csv"
    with pytest.raises(FileNotFoundError):
        main.read_emails_from_csv(str(missing))


def test_write_results_csv_writes_file_in_tests_dir(tmp_path: Path):
    tests_dir = Path(__file__).resolve().parent
    out = tests_dir / "test_output_results.csv"

    results = [
        main.ScreenResult("a@example.com", True, ["example.com"], ""),
        main.ScreenResult("b@example.com", False, [], ""),
    ]

    main.write_results_csv(out, results)

    assert out.exists()
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "email_address,breached,breach_media_summary,breached_sources"


class FakeClient:
    def __init__(self, cfg):
        self.cfg = cfg
        self.start_calls = 0
        self.fetch_calls = 0

    async def start_search(self, term: str, correlation_id: str) -> str:
        self.start_calls += 1
        return "search-id-123"

    async def fetch_results(
        self,
        search_id: str,
        correlation_id: str,
        limit: int,
        offset: int,
    ) -> Dict[str, Any]:
        self.fetch_calls += 1

        return {
            "records": [
                {"name": "https://verifications.io/leak"},
                {"name": "This mentions teespring.com in text"},
                {"name": "2.txt"},
            ]
        }


@pytest.mark.asyncio
async def test_screen_email_parses_sources(monkeypatch):
    monkeypatch.setattr(main.asyncio, "sleep", _no_sleep)

    cfg = main.IntelXConfig(
        base_url="https://example.test",
        api_key_env="INTELX_API_KEY",
        requests_per_second=1000.0,
        timeout_connect=0.1,
        timeout_read=0.1,
        max_retries=1,
        backoff_initial_seconds=0.0,
        backoff_max_seconds=0.0,
        retry_on_status=(429,),
        max_results=40,
        search_timeout_seconds=0,
        sort=2,
        lookuplevel=0,
        buckets=[],
        result_poll_attempts=1,
        result_poll_initial_delay_seconds=0.0,
        max_concurrency=5,
    )

    client = FakeClient(cfg)
    logger = main.setup_logger("INFO")

    result = await main.screen_email(client, "test@example.com", logger)

    assert result.breached is True
    assert "verifications.io" in result.site_where_breached
    assert "teespring.com" in result.site_where_breached
    assert client.start_calls == 1
    assert client.fetch_calls >= 1


@pytest.mark.asyncio
async def test_screen_email_invalid_email_short_circuits(monkeypatch):
    monkeypatch.setattr(main.asyncio, "sleep", _no_sleep)

    cfg = Mock()
    cfg.result_poll_attempts = 1
    cfg.result_poll_initial_delay_seconds = 0.0
    cfg.max_results = 40
    cfg.backoff_max_seconds = 0.0

    client = Mock()
    client.cfg = cfg
    client.start_search = AsyncMock()
    client.fetch_results = AsyncMock()

    logger = main.setup_logger("INFO")

    res = await main.screen_email(client, "not-an-email", logger)

    assert res.breached is False
    assert res.site_where_breached == []
    client.start_search.assert_not_called()
    client.fetch_results.assert_not_called()


class FakeResponse:
    def __init__(
        self,
        status_code: int,
        json_data: Optional[Dict[str, Any]] = None,
        text: str = "",
    ):
        self.status_code = status_code
        self._json_data = json_data or {}
        self.text = text
        self.headers: Dict[str, str] = {}

    def json(self) -> Dict[str, Any]:
        return self._json_data


def make_client_for_request_tests(monkeypatch) -> main.IntelXClient:
    monkeypatch.setenv("INTELX_API_KEY", "dummy")

    cfg = main.IntelXConfig(
        base_url="https://example.test",
        api_key_env="INTELX_API_KEY",
        requests_per_second=1000.0,
        timeout_connect=0.01,
        timeout_read=0.01,
        max_retries=5,
        backoff_initial_seconds=0.1,
        backoff_max_seconds=0.2,
        retry_on_status=(429, 500, 502, 503, 504),
        max_results=40,
        search_timeout_seconds=0,
        sort=2,
        lookuplevel=0,
        buckets=[],
        result_poll_attempts=1,
        result_poll_initial_delay_seconds=0.0,
        max_concurrency=5,
    )

    app = main.AppConfig(log_level="INFO", user_agent="test-agent")
    logger = main.setup_logger("INFO")

    return main.IntelXClient(cfg, app, logger)


@pytest.mark.asyncio
async def test_request_retries_on_429_then_succeeds(monkeypatch):
    monkeypatch.setattr(main.asyncio, "sleep", _no_sleep)

    client = make_client_for_request_tests(monkeypatch)

    try:
        client.ratelimiter.wait = AsyncMock(return_value=None)

        client._client.request = AsyncMock(side_effect=[FakeResponse(429), FakeResponse(200)])

        resp = await client._request("GET", "/x", correlation_id="cid-1")

        assert resp.status_code == 200
        assert client._client.request.call_count == 2

    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_request_retries_on_network_error_then_succeeds(monkeypatch):
    monkeypatch.setattr(main.asyncio, "sleep", _no_sleep)

    client = make_client_for_request_tests(monkeypatch)

    try:
        client.ratelimiter.wait = AsyncMock(return_value=None)

        req = httpx.Request("GET", "https://example.test/x")
        err = httpx.ConnectError("error", request=req)

        client._client.request = AsyncMock(side_effect=[err, FakeResponse(200)])

        resp = await client._request("GET", "/x", correlation_id="cid-2")

        assert resp.status_code == 200
        assert client._client.request.call_count == 2

    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_request_exhausts_retries_and_raises(monkeypatch):
    monkeypatch.setattr(main.asyncio, "sleep", _no_sleep)

    client = make_client_for_request_tests(monkeypatch)

    try:
        client.ratelimiter.wait = AsyncMock(return_value=None)

        client._client.request = AsyncMock(side_effect=[FakeResponse(500)] * client.cfg.max_retries)

        with pytest.raises(RuntimeError):
            await client._request("GET", "/x", correlation_id="cid-3")

        assert client._client.request.call_count == client.cfg.max_retries

    finally:
        await client.aclose()


def test_is_valid_email_trims_whitespace():
    assert main.is_valid_email("  test@example.com  ")


def test_correlation_id_for_is_deterministic_and_12_chars():
    cid1 = main.correlation_id_for("Test@Example.com")
    cid2 = main.correlation_id_for("test@example.com")

    assert cid1 == cid2
    assert len(cid1) == 12


def test_extract_source_domain_from_url():
    item = {"name": "https://sub.example.com/path/to/page"}
    assert main.extract_source_domain(item) == "sub.example.com"


def test_extract_source_domain_from_text_domain():
    item = {"name": "Leak posted on example.org in a forum"}
    assert main.extract_source_domain(item) == "example.org"


def test_extract_source_domain_returns_none_when_missing_name():
    assert main.extract_source_domain({}) is None
    assert main.extract_source_domain({"name": ""}) is None


def test_extract_source_domain_bad_url_returns_none():
    item = {"name": "https://"}
    assert main.extract_source_domain(item) is None


def test_read_emails_from_csv_strips_and_keeps_order(tmp_path: Path):
    csv_path = tmp_path / "emails.csv"
    csv_path.write_text(
        "email_address\n" "  a@example.com  \n" "\n" "b@example.com\n",
        encoding="utf-8",
    )

    emails = main.read_emails_from_csv(str(csv_path))
    assert emails == ["a@example.com", "b@example.com"]


class PollingClient:
    def __init__(self, cfg):
        self.cfg = cfg
        self.calls = 0

    async def start_search(self, term: str, correlation_id: str) -> str:
        return "search-1"

    async def fetch_results(self, search_id: str, correlation_id: str, limit: int, offset: int):
        self.calls += 1

        if self.calls == 1:
            return {"records": []}

        return {"records": [{"name": "https://example.com/leak"}]}


@pytest.mark.asyncio
async def test_screen_email_polls_until_records_found(monkeypatch):
    monkeypatch.setattr(main.asyncio, "sleep", _no_sleep)

    cfg = main.IntelXConfig(
        base_url="https://example.test",
        api_key_env="INTELX_API_KEY",
        requests_per_second=1000.0,
        timeout_connect=0.1,
        timeout_read=0.1,
        max_retries=1,
        backoff_initial_seconds=0.0,
        backoff_max_seconds=1.0,
        retry_on_status=(429,),
        max_results=40,
        search_timeout_seconds=0,
        sort=2,
        lookuplevel=0,
        buckets=[],
        result_poll_attempts=3,
        result_poll_initial_delay_seconds=0.0,
        max_concurrency=5,
    )

    client = PollingClient(cfg)
    logger = main.setup_logger("INFO")

    res = await main.screen_email(client, "test@example.com", logger)

    assert res.breached is True
    assert "example.com" in res.site_where_breached
    assert client.calls == 2


@pytest.mark.asyncio
async def test_request_does_not_retry_on_non_retry_status(monkeypatch):
    monkeypatch.setattr(main.asyncio, "sleep", _no_sleep)

    client = make_client_for_request_tests(monkeypatch)

    try:
        client.ratelimiter.wait = AsyncMock(return_value=None)
        client._client.request = AsyncMock(side_effect=[FakeResponse(404)])

        resp = await client._request("GET", "/x", correlation_id="cid-404")

        assert resp.status_code == 404
        assert client._client.request.call_count == 1

    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_request_honours_retry_after_header(monkeypatch):
    client = make_client_for_request_tests(monkeypatch)

    try:
        client.ratelimiter.wait = AsyncMock(return_value=None)

        r1 = FakeResponse(429)
        r1.headers["Retry-After"] = "7"
        r2 = FakeResponse(200)

        client._client.request = AsyncMock(side_effect=[r1, r2])

        sleep_spy = AsyncMock(return_value=None)
        monkeypatch.setattr(main.asyncio, "sleep", sleep_spy)

        resp = await client._request("GET", "/x", correlation_id="cid-ra")

        assert resp.status_code == 200
        assert sleep_spy.call_count >= 1

    finally:
        await client.aclose()


def test_build_analyst_summary_counts_and_top_sources():
    results = [
        main.ScreenResult("a@example.com", True, ["x.com", "y.com"], ""),
        main.ScreenResult("b@example.com", True, ["x.com"], ""),
        main.ScreenResult("c@example.com", False, [], ""),
        main.ScreenResult("d@example.com", True, ["z.com", "x.com"], ""),
    ]

    summary = main.build_analyst_summary(results, top_n=2)

    assert summary["total_emails"] == 4
    assert summary["breached_emails"] == 3
    assert summary["unique_sources"] == 3

    assert summary["top_sources"][0]["domain"] == "x.com"
    assert summary["top_sources"][0]["count"] == 3
    assert len(summary["top_sources"]) == 2
    assert summary["top_sources"][1]["count"] == 1


def test_write_summary_csv_writes_expected_layout(tmp_path: Path):
    summary = {
        "total_emails": 3,
        "breached_emails": 2,
        "unique_sources": 2,
        "top_sources": [
            {"domain": "example.com", "count": 2},
            {"domain": "foo.com", "count": 1},
        ],
    }

    out = tmp_path / "breach_summary.csv"
    main.write_summary_csv(out, summary)

    assert out.exists()

    lines = out.read_text(encoding="utf-8").splitlines()

    assert lines[0] == "metric,value"
    assert lines[1] == "total_emails,3"
    assert lines[2] == "breached_emails,2"
    assert lines[3] == "unique_sources,2"

    assert lines[4] == ""
    assert lines[5] == "top_breached_sources,count"

    assert lines[6] == "example.com,2"
    assert lines[7] == "foo.com,1"


def test_write_breach_chart_png_creates_file_when_breaches_exist(tmp_path: Path):
    out = tmp_path / "breach_summary.png"

    results = [
        main.ScreenResult("a@example.com", True, ["example.com", "foo.com"], ""),
        main.ScreenResult("b@example.com", True, ["example.com"], ""),
        main.ScreenResult("c@example.com", False, [], ""),
    ]

    main.write_breach_chart_png(out, results, top_n=10)

    assert out.exists()
    data = out.read_bytes()

    assert data.startswith(b"\x89PNG\r\n\x1a\n")
    assert out.stat().st_size > 100


def test_write_breach_chart_png_skips_when_no_breaches(tmp_path: Path):
    out = tmp_path / "breach_summary.png"

    results = [
        main.ScreenResult("a@example.com", False, [], ""),
        main.ScreenResult("b@example.com", False, [], ""),
    ]

    main.write_breach_chart_png(out, results, top_n=10)

    assert not out.exists()
