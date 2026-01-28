import sys
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import Mock

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import main  # noqa: E402


# -----------------------
# CSV I/O
# -----------------------
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


def test_write_results_csv_writes_file_in_tests_dir():
    tests_dir = Path(__file__).resolve().parent
    out = tests_dir / "test_output_results.csv"

    results = [
        main.ScreenResult("a@example.com", True, ["example.com"]),
        main.ScreenResult("b@example.com", False, []),
    ]

    main.write_results_csv(out, results)

    assert out.exists()
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "email_address,breached,site_where_breached"


# -----------------------
# Response parsing via screen_email
# (No real IntelX calls)
# -----------------------
class FakeClient:
    """Minimal fake of IntelXClient used to test screen_email parsing."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.start_calls = 0
        self.fetch_calls = 0

    def start_search(self, term: str, correlation_id: str) -> str:
        self.start_calls += 1
        return "search-id-123"

    def fetch_results(
        self,
        search_id: str,
        correlation_id: str,
        limit: int,
        offset: int,
    ) -> Dict[str, Any]:
        self.fetch_calls += 1
        # Simulate IntelX-like payload
        return {
            "records": [
                {"name": "https://verifications.io/leak"},
                {"name": "This mentions teespring.com in text"},
                {"name": "2.txt (should not really be a domain)"},
            ]
        }


def test_screen_email_parses_sources(monkeypatch):
    # Avoid real sleeps from polling loop
    monkeypatch.setattr(main.time, "sleep", lambda _: None)

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
    )

    client = FakeClient(cfg)
    logger = main.setup_logger("INFO")

    result = main.screen_email(client, "test@example.com", logger)

    assert result.breached is True
    assert "verifications.io" in result.site_where_breached
    assert "teespring.com" in result.site_where_breached
    assert client.start_calls == 1
    assert client.fetch_calls >= 1


def test_screen_email_invalid_email_short_circuits():
    cfg = Mock()
    cfg.result_poll_attempts = 1
    cfg.result_poll_initial_delay_seconds = 0.0
    cfg.max_results = 40
    cfg.backoff_max_seconds = 0.0

    client = Mock()
    client.cfg = cfg
    logger = main.setup_logger("INFO")

    res = main.screen_email(client, "not-an-email", logger)

    assert res.breached is False
    assert res.site_where_breached == []
    client.start_search.assert_not_called()
    client.fetch_results.assert_not_called()


# -----------------------
# Retry logic tests for IntelXClient._request
# (No real HTTP calls)
# -----------------------
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
    )

    app = main.AppConfig(log_level="INFO", user_agent="test-agent")
    logger = main.setup_logger("INFO")

    client = main.IntelXClient(cfg, app, logger)

    # Avoid real sleeps in retry/backoff logic
    monkeypatch.setattr(main.time, "sleep", lambda _: None)
    client.ratelimiter.wait = lambda: None

    return client


def test_request_retries_on_429_then_succeeds(monkeypatch):
    client = make_client_for_request_tests(monkeypatch)

    client.session.request = Mock(side_effect=[FakeResponse(429), FakeResponse(200)])

    resp = client._request("GET", "/x", correlation_id="cid-1")

    assert resp.status_code == 200
    assert client.session.request.call_count == 2  # proves retry occurred


def test_request_retries_on_network_error_then_succeeds(monkeypatch):
    client = make_client_for_request_tests(monkeypatch)

    client.session.request = Mock(
        side_effect=[requests.ConnectionError("error"), FakeResponse(200)]
    )

    resp = client._request("GET", "/x", correlation_id="cid-2")

    assert resp.status_code == 200
    assert client.session.request.call_count == 2


def test_request_exhausts_retries_and_raises(monkeypatch):
    client = make_client_for_request_tests(monkeypatch)

    client.session.request = Mock(side_effect=[FakeResponse(500)] * client.cfg.max_retries)

    with pytest.raises(RuntimeError):
        client._request("GET", "/x", correlation_id="cid-3")

    assert client.session.request.call_count == client.cfg.max_retries
