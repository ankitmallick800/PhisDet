from pathlib import Path

from phishdet.parse import looks_like_raw_email, parse_email
from phishdet.textutil import normalize_text

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "src" / "phishdet" / "samples"


def test_normalize_replaces_urls_and_tags():
    text = normalize_text("Verify <b>NOW</b> at https://paypa1.com/login")
    assert "paypa1" not in text
    assert "url" in text
    assert "<b>" not in text
    assert text == text.lower()


def test_loose_text_is_not_treated_as_headers():
    parsed = parse_email("From the team:\nThe build is green.\n")
    assert parsed.is_raw_email is False
    assert "build is green" in parsed.text


def test_raw_email_keeps_headers_and_html_links():
    parsed = parse_email((SAMPLES / "phishing.eml").read_text(encoding="utf-8"))
    assert parsed.is_raw_email is True
    assert parsed.subject.startswith("Your PayPal")
    assert "paypa1.com" in parsed.from_header
    assert parsed.has_password_field is True
    assert any(link.href.startswith("http://paypa1.com") for link in parsed.links)
    assert "paypal.com" in parsed.text.lower() or any("paypal.com" in link.text for link in parsed.links)


def test_multipart_prefers_plain_text_and_keeps_html_links():
    raw = """\
From: A <a@example.com>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary=abc

--abc
Content-Type: text/plain; charset=utf-8

Hello plain https://example.com/a

--abc
Content-Type: text/html; charset=utf-8

<p>Hello <a href="https://evil.test/x">https://example.com/a</a></p>
<input type="password" name="password">
--abc--
"""
    parsed = parse_email(raw)
    assert "Hello plain" in parsed.text
    assert parsed.has_password_field is True
    assert any(link.href == "https://evil.test/x" for link in parsed.links)


def test_mbox_from_line_still_parses():
    raw = "From user@example.com Mon Nov 3\nFrom: Ada <ada@example.com>\nSubject: Hi\n\nBody\n"
    assert looks_like_raw_email(raw)
    parsed = parse_email(raw)
    assert parsed.subject == "Hi"
    assert "ada@example.com" in parsed.from_header


def test_msg_file_is_rejected():
    try:
        parse_email(b"\xd0\xcf\x11\xe0rest")
    except ValueError as exc:
        assert ".msg" in str(exc)
    else:
        raise AssertionError("expected ValueError")
