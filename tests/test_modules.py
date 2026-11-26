import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from remi_core import cve_monitor, report_generator, system_checker


def test_load_profile_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(cve_monitor, "CONFIG_PATH", str(tmp_path / "missing.json"))
    profile = cve_monitor.load_profile()
    assert profile["monitored_subsystems"] == ["kernel", "mptcp", "openssl"]


def test_fetch_cve_alerts_filters_cvss(monkeypatch):
    sample_payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-0001",
                    "descriptions": [{"lang": "en", "value": "Critical test issue"}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 9.1}}]
                    },
                }
            },
            {
                "cve": {
                    "id": "CVE-2026-0002",
                    "descriptions": [{"lang": "en", "value": "Low severity issue"}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 4.0}}]
                    },
                }
            },
        ]
    }
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = json.dumps(sample_payload).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        alerts = cve_monitor.fetch_cve_alerts("openssl", cvss_min=7.5)

    assert len(alerts) == 1
    assert alerts[0]["cve_id"] == "CVE-2026-0001"
    assert alerts[0]["cvss"] == 9.1


def test_generate_summary_report_creates_json_and_md(tmp_path, monkeypatch):
    feeds_dir = tmp_path / "feeds"
    reports_dir = tmp_path / "reports"
    feeds_dir.mkdir()

    feed_data = [
        {
            "cve_id": "CVE-2026-9999",
            "cvss": 8.8,
            "subsystem": "kernel",
            "description": "High priority kernel finding.",
        }
    ]
    (feeds_dir / "cve_feed_20261126_120000.json").write_text(
        json.dumps(feed_data), encoding="utf-8"
    )

    monkeypatch.setattr(report_generator, "FEEDS_DIR", str(feeds_dir))
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(reports_dir))
    monkeypatch.setattr(report_generator, "send_telemetry_to_suite", lambda _: False)

    out_json, out_md = report_generator.generate_summary_report(min_cvss=8.0)

    assert out_json is not None and Path(out_json).exists()
    assert out_md is not None and Path(out_md).exists()
    assert "CVE-2026-9999" in Path(out_md).read_text(encoding="utf-8")


def test_audit_local_system_matches_packages(tmp_path, monkeypatch):
    feeds_dir = tmp_path / "feeds"
    feeds_dir.mkdir()
    feed_data = [
        {
            "cve_id": "CVE-2026-1234",
            "cvss": 8.2,
            "subsystem": "openssl",
            "description": "OpenSSL issue",
        }
    ]
    (feeds_dir / "cve_feed_20261126_120000.json").write_text(
        json.dumps(feed_data), encoding="utf-8"
    )

    monkeypatch.setattr(system_checker, "FEEDS_DIR", str(feeds_dir))
    monkeypatch.setattr(
        system_checker,
        "get_installed_packages",
        lambda: {"openssl": "3.0.13-0ubuntu3", "bash": "5.1-6ubuntu1"},
    )

    matches = system_checker.audit_local_system()
    assert len(matches) == 1
    assert matches[0]["package"] == "openssl"
    assert matches[0]["cve_id"] == "CVE-2026-1234"
