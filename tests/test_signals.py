from pathlib import Path

from phishdet.parse import parse_email
from phishdet.signals import BRANDS, extract_signals, host_impersonates, host_is_official, registrable

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "src" / "phishdet" / "samples"


def _brand(key: str):
    return next(brand for brand in BRANDS if brand.key == key)


def _codes(raw: str) -> set[str]:
    return {item.code for item in extract_signals(parse_email(raw))}


def test_registrable_domain_handles_multipart_suffixes():
    assert registrable("mail.example.co.uk") == "example.co.uk"
    assert registrable("login.github.com") == "github.com"


def test_lookalike_hosts():
    paypal = _brand("paypal")
    apple = _brand("apple")
    amazon = _brand("amazon")
    assert host_impersonates("paypa1.com", paypal, mentioned=False)
    assert host_impersonates("notpaypal.com", paypal, mentioned=False)
    assert host_impersonates("paypal.com.evil.test", paypal, mentioned=False)
    assert host_impersonates("paypal-secure.com", paypal, mentioned=False)
    assert not host_impersonates("login.paypal.com", paypal, mentioned=True)
    assert not host_impersonates("paypal.com", paypal, mentioned=True)
    assert host_is_official("paypal.de", paypal)
    assert not host_impersonates("apple-farm.com", apple, mentioned=False)
    assert host_impersonates("apple-secure.com", apple, mentioned=False)
    assert not host_impersonates("s3.amazonaws.com", amazon, mentioned=True)
    assert not host_impersonates("login.github.com", _brand("github"), mentioned=True)


def test_phishing_sample_has_deceptive_link_signals():
    raw = (SAMPLES / "phishing.eml").read_text(encoding="utf-8")
    codes = _codes(raw)
    assert "brand_impersonation" in codes
    assert "href_mismatch" in codes
    assert "password_form" in codes
    assert "links_match_known_sender" not in codes
    indicators = extract_signals(parse_email(raw))
    mismatch = next(item for item in indicators if item.code == "href_mismatch")
    assert "paypa1.com" in mismatch.detail
    assert "paypal.com" in mismatch.detail
    for item in indicators:
        if item.code == "pressure_external_link":
            assert "paypal.com" not in item.detail


def test_github_reset_links_match_the_known_sender():
    raw = (SAMPLES / "reset.eml").read_text(encoding="utf-8")
    codes = _codes(raw)
    assert "links_match_known_sender" in codes
    assert "brand_impersonation" not in codes
    assert "password_form" not in codes


def test_work_note_has_no_risk_signals():
    raw = (SAMPLES / "legitimate.eml").read_text(encoding="utf-8")
    weights = [item.weight for item in extract_signals(parse_email(raw))]
    assert not any(weight > 0 for weight in weights)


def test_bec_sample_flags_freemail_payment():
    raw = (SAMPLES / "bec.eml").read_text(encoding="utf-8")
    codes = _codes(raw)
    assert "freemail_payment" in codes


def test_fruit_and_ordinary_words_do_not_invent_a_brand():
    raw = """\
From: Sam <sam@orchard.example>
Subject: Saturday
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

I ate an apple under the tree. The outlook is good if the rain holds.
https://orchard.example/photos
"""
    codes = _codes(raw)
    assert "brand_impersonation" not in codes
    assert "display_name_impersonation" not in codes


def test_display_name_hides_a_different_address():
    raw = """\
From: "support@paypal.com" <attacker@gmail.com>
Subject: Account
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Please review.
"""
    codes = _codes(raw)
    assert "display_name_address_mismatch" in codes
    assert "display_name_impersonation" in codes


def test_ip_and_at_sign_links():
    raw = """\
From: Alerts <alerts@example.com>
Subject: Sign in
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Open http://192.0.2.10/login and http://paypal.com@evil.test/account
"""
    codes = _codes(raw)
    assert "ip_url" in codes
    assert "at_sign_url" in codes
