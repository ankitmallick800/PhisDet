import json
import threading
from pathlib import Path
from urllib.request import Request, urlopen

from phishdet.cli import main
from phishdet.detect import detect
from phishdet.model import load_bundle
from phishdet.server import make_server

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "src" / "phishdet" / "samples"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_model_meets_the_held_out_bar():
    metrics = load_bundle()["metrics"]
    assert metrics["f1"] >= 0.9
    assert metrics["recall"] >= 0.9
    assert metrics["precision"] >= 0.9


def test_obvious_phishing_is_phishing():
    verdict = detect((SAMPLES / "phishing.eml").read_text(encoding="utf-8"))
    assert verdict.label == "phishing"
    assert verdict.phishing_probability >= 0.8
    assert any(item.code == "href_mismatch" for item in verdict.indicators)


def test_password_reset_from_the_real_domain_stays_legitimate():
    verdict = detect((SAMPLES / "reset.eml").read_text(encoding="utf-8"))
    assert verdict.label == "legitimate"
    assert verdict.phishing_probability <= 0.45


def test_ordinary_work_mail_stays_legitimate():
    verdict = detect((SAMPLES / "legitimate.eml").read_text(encoding="utf-8"))
    assert verdict.label == "legitimate"
    assert verdict.phishing_probability < 0.5


def test_newsletter_with_matching_links_stays_legitimate():
    verdict = detect((FIXTURES / "newsletter.eml").read_text(encoding="utf-8"))
    assert verdict.label == "legitimate"


def test_wire_transfer_lure_is_phishing():
    verdict = detect((SAMPLES / "bec.eml").read_text(encoding="utf-8"))
    assert verdict.label == "phishing"
    assert any(item.code == "freemail_payment" for item in verdict.indicators)


def test_consistent_unknown_domain_with_a_classic_lure_is_phishing():
    verdict = detect((FIXTURES / "lookalike.eml").read_text(encoding="utf-8"))
    assert verdict.label == "phishing"
    assert verdict.phishing_probability >= 0.6


def test_short_ordinary_note_is_not_phishing():
    raw = """\
From: Sam <sam@orchard.example>
Subject: Saturday

I ate an apple under the tree. The build is green.
"""
    verdict = detect(raw)
    assert verdict.label == "legitimate"
    assert not any(item.weight > 0 for item in verdict.indicators)


def test_empty_input_is_rejected():
    try:
        detect("   ")
    except ValueError as exc:
        assert "Paste" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_cli_json_and_sample(capsys):
    assert main(["--sample", "legitimate", "--json", "--no-color"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["label"] == "legitimate"


def test_http_detect_round_trip():
    server = make_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        health = json.loads(urlopen(f"http://127.0.0.1:{port}/api/health").read())
        assert health["ok"] is True
        page = urlopen(f"http://127.0.0.1:{port}/").read().decode("utf-8")
        assert "Check an email" in page
        assert "/api/detect" in page
        sample = urlopen(f"http://127.0.0.1:{port}/api/sample/phishing").read()
        request = Request(
            f"http://127.0.0.1:{port}/api/detect",
            data=json.dumps({"email": sample.decode("utf-8")}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        body = json.loads(urlopen(request).read())
        assert body["label"] == "phishing"
        assert body["reasons"]
        empty = Request(
            f"http://127.0.0.1:{port}/api/detect",
            data=json.dumps({"email": "  "}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urlopen(empty)
        except Exception as exc:
            assert getattr(exc, "code", None) == 400
        else:
            raise AssertionError("expected HTTP 400")
    finally:
        server.shutdown()
        server.server_close()
