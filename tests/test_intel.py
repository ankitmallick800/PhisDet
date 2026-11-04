"""Reputation lookups stay offline. HTTP is mocked at the lookup boundary."""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

from phishdet.cli import main
from phishdet.detect import detect
from phishdet.intel import (
    age_days,
    age_from_rdap,
    clear_cache,
    external_indicators,
    investigate,
    local_view,
    public_domain,
    urlscan_from_search,
    vt_from_domain,
)
from phishdet.parse import parse_email
from phishdet.server import make_server
from phishdet.signals import authentication_summary

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "src" / "phishdet" / "samples"
NOW = datetime(2026, 11, 4, tzinfo=timezone.utc)


def _report(domain: str, **overrides) -> dict:
    base = {
        "domain": domain,
        "age_days": None,
        "registered": "",
        "age_status": "no_record",
        "vt_malicious": None,
        "vt_url_malicious": None,
        "urlscan_malicious": None,
    }
    base.update(overrides)
    return base


def test_authentication_results_are_read_and_scored():
    raw = """From: Ada <ada@b.com>
Authentication-Results: mx.example.net; spf=fail smtp.mailfrom=b.com; dkim=pass; dmarc=fail
Received-SPF: pass
DKIM-Signature: v=1; a=rsa-sha256; d=b.com;
Subject: hi
Content-Type: text/plain; charset=utf-8

Hello there, this is a short note.
"""
    parsed = parse_email(raw)
    summary = authentication_summary(parsed)
    assert summary["spf"] == "fail"
    assert summary["dkim"] == "pass"
    assert summary["dmarc"] == "fail"
    assert parsed.has_dkim_signature
    verdict = detect(raw)
    codes = {item.code for item in verdict.indicators}
    assert "spf_fail" in codes
    assert "dmarc_fail" in codes
    assert "dkim_fail" not in codes
    detail = next(item.detail for item in verdict.indicators if item.code == "dmarc_fail")
    assert "mail server" in detail or "sender" in detail


def test_softfail_is_not_scored_as_fail():
    raw = """From: Ada <ada@b.com>
Authentication-Results: mx.example.net; spf=softfail
Subject: hi
Content-Type: text/plain; charset=utf-8

Hello there, this is a short note.
"""
    assert authentication_summary(parse_email(raw))["spf"] == "softfail"
    assert all(item.code != "spf_fail" for item in detect(raw).indicators)


def test_json_body_decodes_objects_only():
    from phishdet.intel import _decode_json

    assert _decode_json(b'{"registered": "2007-10-09T18:20:50Z"}')["registered"].startswith("2007")
    assert _decode_json(b"[]") is None
    assert _decode_json(b"not json") is None


def test_age_from_rdap_reads_registration():
    payload = {
        "events": [
            {"eventAction": "registration", "eventDate": "2007-10-09T18:20:50Z"},
            {"eventAction": "expiration", "eventDate": "2028-10-09T18:20:50Z"},
        ]
    }
    parsed = age_from_rdap(payload)
    assert parsed["registered"].startswith("2007-10-09")
    assert age_days(parsed["registered"], now=NOW) == (NOW.date() - datetime(2007, 10, 9).date()).days


def test_young_domain_is_a_reason_and_a_missing_record_is_not():
    young = external_indicators([_report("new-example.com", age_days=10, registered="2026-10-25T00:00:00Z")])
    assert any(item.code == "young_domain" and item.weight == 1.6 for item in young)
    assert external_indicators([_report("older.example")]) == []
    recent = external_indicators([_report("recent.example", age_days=40)])
    assert any(item.code == "recent_domain" and item.weight == 0.9 for item in recent)
    old = external_indicators([_report("github.com", age_days=6000, registered="2007-10-09")])
    assert old == []


def test_virustotal_and_urlscan_parsers():
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 4, "suspicious": 1, "harmless": 10, "undetected": 2},
                "creation_date": 1191954050,
            }
        }
    }
    parsed = vt_from_domain(payload)
    assert parsed["malicious"] == 4
    assert parsed["creation_date"] == 1191954050
    flagged = external_indicators([_report("paypa1.com", vt_malicious=4)])
    assert any(item.code == "virustotal_malicious" and item.weight == 2.0 for item in flagged)

    unrelated = {
        "results": [{
            "task": {"domain": "release-assets.githubusercontent.com", "apexDomain": "github.com", "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
            "page": {"domain": "release-assets.githubusercontent.com", "domainAgeDays": 554},
            "_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        }]
    }
    scan = urlscan_from_search(unrelated, "github.com")
    assert scan["malicious"] is None
    assert scan["status"] == "unrelated"
    assert "554" not in scan["detail"]

    malicious = {
        "results": [{
            "task": {"domain": "paypa1.com", "uuid": "11111111-1111-1111-1111-111111111111"},
            "page": {"domain": "paypa1.com"},
            "verdicts": {"overall": {"malicious": True}},
            "_id": "11111111-1111-1111-1111-111111111111",
        }]
    }
    hit = urlscan_from_search(malicious, "paypa1.com")
    assert hit["malicious"] is True
    assert hit["link"] == "https://urlscan.io/result/11111111-1111-1111-1111-111111111111/"


def test_public_domain_skips_private_and_reserved_names():
    assert public_domain("127.0.0.1") == ""
    assert public_domain("10.1.2.3") == ""
    assert public_domain("localhost") == ""
    assert public_domain("mail.example.com") == ""
    assert public_domain("team.example") == ""
    assert public_domain("login.github.com") == "github.com"
    assert public_domain("evil.test") == ""


def test_local_view_does_not_treat_example_as_a_lookup():
    report = local_view((SAMPLES / "legitimate.eml").read_text(encoding="utf-8"))
    assert report["label"] == "legitimate"
    assert report["resources"] == []
    assert report["intel"]["status"] == "pending"
    assert report["headers"]["spf"] == "none"


def test_investigate_adds_a_young_domain_without_network(monkeypatch):
    clear_cache()
    calls = []

    def fake(domain, urls, include_url):
        calls.append(domain)
        return {
            "domain": domain,
            "roles": [],
            "urls": list(urls or []),
            "age_days": 5,
            "registered": "2026-10-30T00:00:00Z",
            "expires": "",
            "age_source": "rdap",
            "age_status": "registered",
            "age_detail": "Registered 2026-10-30 (5 days ago) via RDAP.",
            "vt_status": "unconfigured",
            "vt_malicious": None,
            "vt_suspicious": None,
            "vt_harmless": None,
            "vt_undetected": None,
            "vt_url_status": "skipped",
            "vt_url_malicious": None,
            "vt_link": f"https://www.virustotal.com/gui/domain/{domain}",
            "vt_detail": "VirusTotal key is not set.",
            "urlscan_status": "none",
            "urlscan_malicious": None,
            "urlscan_link": "",
            "urlscan_detail": "No public urlscan report.",
        }

    monkeypatch.setattr("phishdet.intel.lookup_domain", fake)
    report = investigate((SAMPLES / "reset.eml").read_text(encoding="utf-8"))
    assert calls == ["github.com"]
    assert any(item["code"] == "young_domain" for item in report["reasons"])
    assert report["resources"][0]["domain"] == "github.com"
    assert "5 days ago" in report["resources"][0]["age_detail"]


def test_old_sender_domain_does_not_lower_a_bec_score(monkeypatch):
    def fake(domain, urls, include_url):
        return {
            "domain": domain,
            "age_days": 8000,
            "registered": "2004-01-01T00:00:00Z",
            "expires": "",
            "age_source": "rdap",
            "age_status": "registered",
            "age_detail": "Registered 2004-01-01 (8000 days ago) via RDAP.",
            "vt_status": "unconfigured",
            "vt_malicious": None,
            "vt_url_malicious": None,
            "vt_url_status": "skipped",
            "vt_suspicious": None,
            "vt_harmless": None,
            "vt_undetected": None,
            "vt_link": "",
            "vt_detail": "VirusTotal key is not set.",
            "urlscan_status": "none",
            "urlscan_malicious": None,
            "urlscan_link": "",
            "urlscan_detail": "No public urlscan report.",
        }

    monkeypatch.setattr("phishdet.intel.lookup_domain", fake)
    raw = (SAMPLES / "bec.eml").read_text(encoding="utf-8")
    before = detect(raw)
    report = investigate(raw)
    assert report["label"] == "phishing"
    assert report["phishing_probability"] == round(before.phishing_probability, 4)
    assert report["resources"][0]["domain"] == "gmail.com"
    assert all(item["code"] != "young_domain" for item in report["reasons"])


def test_http_intel_uses_the_lookup_stub(monkeypatch):
    def fake(domain, urls, include_url):
        return {
            "domain": domain,
            "age_days": None,
            "registered": "",
            "expires": "",
            "age_source": "",
            "age_status": "no_record",
            "age_detail": "No RDAP registration record. That is not treated as a new domain.",
            "vt_status": "unconfigured",
            "vt_malicious": None,
            "vt_url_malicious": None,
            "vt_url_status": "skipped",
            "vt_suspicious": None,
            "vt_harmless": None,
            "vt_undetected": None,
            "vt_link": "",
            "vt_detail": "VirusTotal key is not set.",
            "urlscan_status": "none",
            "urlscan_malicious": None,
            "urlscan_link": "",
            "urlscan_detail": "No public urlscan report.",
        }

    monkeypatch.setattr("phishdet.intel.lookup_domain", fake)
    server = make_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        health = json.loads(urlopen(f"http://127.0.0.1:{port}/api/health").read())
        assert "services" in health
        assert health["services"]["rdap"] is True
        page = urlopen(f"http://127.0.0.1:{port}/").read().decode("utf-8")
        assert "/api/intel" in page
        assert "VirusTotal" in page
        sample = (SAMPLES / "reset.eml").read_text(encoding="utf-8")
        request = Request(
            f"http://127.0.0.1:{port}/api/intel",
            data=json.dumps({"email": sample}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        body = json.loads(urlopen(request, timeout=10).read())
        assert body["intel"]["status"] == "done"
        assert body["resources"][0]["domain"] == "github.com"
        assert body["resources"][0]["age_status"] == "no_record"
        assert body["label"] == "legitimate"
    finally:
        server.shutdown()
        server.server_close()


def test_cli_intel_json_stays_offline(monkeypatch, capsys):
    monkeypatch.setattr(
        "phishdet.intel.lookup_domain",
        lambda domain, urls, include_url: {
            "domain": domain,
            "age_days": None,
            "registered": "",
            "expires": "",
            "age_source": "",
            "age_status": "unavailable",
            "age_detail": "Domain age lookup did not respond.",
            "vt_status": "unconfigured",
            "vt_malicious": None,
            "vt_url_malicious": None,
            "vt_url_status": "skipped",
            "vt_suspicious": None,
            "vt_harmless": None,
            "vt_undetected": None,
            "vt_link": "",
            "vt_detail": "VirusTotal key is not set.",
            "urlscan_status": "error",
            "urlscan_malicious": None,
            "urlscan_link": "",
            "urlscan_detail": "urlscan did not respond.",
        },
    )
    assert main(["--sample", "legitimate", "--intel", "--json", "--no-color"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["label"] == "legitimate"
    assert payload["resources"] == []
    assert payload["intel"]["status"] == "done"
