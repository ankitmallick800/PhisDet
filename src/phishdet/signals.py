"""Sender, link, and wording signals that sit beside the text model.

The text model learns phrasing from a public corpus. These checks look at
the parts of a raw email that corpus does not represent well: who the message
claims to be, and where its links actually go. Nothing here contacts the network.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from email.utils import parseaddr
from urllib.parse import urlparse

from phishdet.parse import ParsedEmail

# A link back to the sender only counts as strong evidence when that sender
# is one of these organizations. A phisher who buys one domain and uses it in
# both the From line and the link looks "consistent" and should not get the
# same benefit.
_SAFE_TLDS = {
    "com",
    "net",
    "org",
    "co.uk",
    "org.uk",
    "de",
    "fr",
    "it",
    "es",
    "nl",
    "ca",
    "com.au",
    "co.jp",
    "eu",
    "us",
    "co.nz",
    "co.in",
    "com.br",
    "com.mx",
    "com.sg",
}
_MULTI_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.jp",
    "co.in",
    "com.br",
    "com.mx",
    "co.nz",
    "co.za",
    "com.sg",
    "com.tr",
    "co.kr",
    "com.cn",
    "com.hk",
    "com.tw",
}
_NEUTRAL_SUFFIXES = (
    "amazonaws.com",
    "cloudfront.net",
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "windows.net",
    "azureedge.net",
    "akamaihd.net",
    "cloudflare.net",
    "sendgrid.net",
    "mailchimp.com",
    "list-manage.com",
    "sparkpostmail.com",
    "mandrillapp.com",
    "exacttarget.com",
    "sailthru.com",
)
_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "tiny.cc",
    "shorturl.at",
    "buff.ly",
    "rebrand.ly",
    "t.ly",
    "tiny.one",
}
_SUSPICIOUS_TLDS = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "zip",
    "mov",
    "buzz",
    "loan",
    "click",
    "country",
    "men",
    "bid",
    "download",
    "racing",
    "accountant",
    "gq",
}
_FREEMAIL = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "yahoo.co.uk",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
    "icloud.com",
    "me.com",
    "gmx.com",
    "mail.com",
    "yandex.com",
    "yandex.ru",
    "zoho.com",
}
_LABEL_SUFFIXES = {
    "secure",
    "login",
    "logon",
    "signin",
    "signon",
    "account",
    "accounts",
    "verify",
    "verification",
    "update",
    "support",
    "service",
    "services",
    "alert",
    "alerts",
    "billing",
    "security",
    "online",
    "auth",
    "recover",
    "recovery",
    "unlock",
    "limited",
    "help",
    "center",
    "centre",
    "mail",
    "email",
    "notification",
    "notifications",
    "invoice",
    "notice",
    "portal",
    "customer",
    "customers",
    "info",
    "team",
    "lock",
    "locked",
    "web",
    "app",
}
_CONFUSABLES = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "і": "i",
        "ѕ": "s",
        "һ": "h",
        "ј": "j",
        "ԁ": "d",
        "ԛ": "q",
        "ԝ": "w",
        "ɡ": "g",
    }
)
_HIGH_RISK_EXTENSIONS = {
    ".exe",
    ".scr",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".bat",
    ".cmd",
    ".pif",
    ".hta",
    ".iso",
    ".img",
    ".lnk",
    ".msi",
    ".dll",
    ".ps1",
    ".wsf",
    ".cpl",
    ".jar",
    ".com",
}
_MED_RISK_EXTENSIONS = {".html", ".htm", ".svg", ".docm", ".xlsm", ".pptm"}
_URL_RE = re.compile(r"(?i)\b((?:https?://|hxxps?://|www\.)[^\s<>'\"]+)")
_BARE_HOST_RE = re.compile(
    r"(?i)^(?:https?://|hxxps?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:].*)?$"
)
_EMBEDDED_ADDRESS = re.compile(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}", re.IGNORECASE)
_CREDENTIAL_RE = re.compile(
    r"(?i)\b(?:"
    r"passwords?|passcodes?|passphrases?|otp|"
    r"one[- ]time (?:code|pin|password)|"
    r"social security|ssn|"
    r"credit cards?|card numbers?|cvv|"
    r"routing numbers?|"
    r"verify your (?:account|identity|e-?mail)|"
    r"confirm your (?:account|identity|password|e-?mail)|"
    r"update your (?:account|payment|billing|information)|"
    r"unlock your account|"
    r"unusual (?:sign|log)[- ]?in"
    r")\b"
)
_URGENCY_RE = re.compile(
    r"(?i)\b(?:"
    r"immediately|urgent|urgently|act now|"
    r"within 24 hours|within 48 hours|"
    r"account (?:will be|has been) (?:closed|suspended|locked|limited|restricted)|"
    r"final notice|last warning|expires today|"
    r"failure to (?:verify|comply|respond)|"
    r"limited time|right away|as soon as possible"
    r")\b"
)
_PAYMENT_RE = re.compile(
    r"(?i)\b(?:"
    r"wire transfers?|wiring instructions?|gift cards?|"
    r"bitcoins?|crypto wallets?|bank transfers?|routing numbers?|"
    r"update (?:the )?(?:payment|banking) details|"
    r"vendor payment|send (?:the )?payment"
    r")\b"
)
_SECRECY_RE = re.compile(
    r"(?i)(?:"
    r"do not (?:tell|share|forward)|"
    r"don't (?:tell|share|forward)|"
    r"keep this (?:quiet|between us)|"
    r"i am in a meeting|i'm in a meeting|"
    r"reply only to me|"
    r"handle this quietly|"
    r"not tell (?:the )?(?:rest|anyone|others)"
    r")"
)
_EXEC_RE = re.compile(
    r"(?i)\b(?:ceo|cfo|chief executive|chief financial|"
    r"president|chair(?:man|woman|person))\b"
)
_TRAILING = ".,);]>'\"”’"


@dataclass(frozen=True)
class Brand:
    key: str
    pattern: re.Pattern[str]
    official: tuple[str, ...]
    names: tuple[str, ...]
    # Company names that are safe to treat as official on ordinary TLDs
    # (paypal.de) without also blessing generic words (office.com).
    auto_names: tuple[str, ...] = ()


def _brand(key: str, pattern: str, official: tuple[str, ...], names: tuple[str, ...], auto: tuple[str, ...] = ()) -> Brand:
    return Brand(key, re.compile(pattern, re.IGNORECASE), official, names, auto)


BRANDS: tuple[Brand, ...] = (
    _brand("paypal", r"\bpaypal\b", ("paypal.com", "paypal.co.uk"), ("paypal",), ("paypal",)),
    _brand(
        "microsoft",
        r"\bmicrosoft\b|\boffice\s?365\b|\boutlook\s+(?:365|mail|account|support)\b",
        (
            "microsoft.com",
            "office.com",
            "office365.com",
            "microsoftonline.com",
            "live.com",
            "outlook.com",
            "sharepoint.com",
            "hotmail.com",
        ),
        ("microsoft", "office365", "outlook"),
        ("microsoft",),
    ),
    _brand(
        "apple",
        r"\bapple\s?id\b|\bicloud\b|\bapple\s+support\b|\bitunes\b|\bapple\.com\b",
        ("apple.com", "icloud.com"),
        ("apple", "icloud", "itunes", "appleid"),
        ("icloud",),
    ),
    _brand(
        "google",
        r"\bgoogle\b|\bgmail\b",
        ("google.com", "gmail.com", "googlemail.com", "youtube.com"),
        ("google", "gmail"),
        ("google",),
    ),
    _brand(
        "amazon",
        r"\bamazon\b",
        ("amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazon.co.jp"),
        ("amazon",),
        ("amazon",),
    ),
    _brand("netflix", r"\bnetflix\b", ("netflix.com",), ("netflix",), ("netflix",)),
    _brand("github", r"\bgithub\b", ("github.com",), ("github",), ("github",)),
    _brand("docusign", r"\bdocusign\b", ("docusign.com", "docusign.net"), ("docusign",), ("docusign",)),
    _brand("dropbox", r"\bdropbox\b", ("dropbox.com",), ("dropbox",), ("dropbox",)),
    _brand("linkedin", r"\blinkedin\b", ("linkedin.com",), ("linkedin",), ("linkedin",)),
    _brand("facebook", r"\bfacebook\b", ("facebook.com", "facebookmail.com"), ("facebook",), ("facebook",)),
    _brand("instagram", r"\binstagram\b", ("instagram.com",), ("instagram",), ("instagram",)),
    _brand("whatsapp", r"\bwhatsapp\b", ("whatsapp.com",), ("whatsapp",), ("whatsapp",)),
    _brand("coinbase", r"\bcoinbase\b", ("coinbase.com",), ("coinbase",), ("coinbase",)),
    _brand("binance", r"\bbinance\b", ("binance.com",), ("binance",), ("binance",)),
    _brand("wellsfargo", r"\bwells\s*fargo\b", ("wellsfargo.com",), ("wellsfargo",), ("wellsfargo",)),
    _brand(
        "bankofamerica",
        r"\bbank\s+of\s+america\b|\bbofa\b",
        ("bankofamerica.com", "bofa.com"),
        ("bankofamerica", "bofa"),
        ("bankofamerica",),
    ),
    _brand("chase", r"\bchase\s+bank\b|\bjpmorgan\b|\bchase\.com\b", ("chase.com", "jpmorgan.com", "jpmchase.com"), ("chase", "jpmorgan"), ("jpmorgan",)),
    _brand("fedex", r"\bfedex\b", ("fedex.com",), ("fedex",), ("fedex",)),
    _brand("dhl", r"\bdhl\b", ("dhl.com",), ("dhl",), ()),
    _brand(
        "ups",
        r"\bups\b",
        ("ups.com",),
        ("ups",),
        (),
    ),
    _brand("irs", r"\birs\b|\binternal revenue\b", ("irs.gov",), ("irs",), ()),
    _brand("adobe", r"\badobe\b", ("adobe.com",), ("adobe",), ("adobe",)),
)


@dataclass(frozen=True)
class Indicator:
    code: str
    weight: float
    title: str
    detail: str

    def to_dict(self) -> dict[str, str | float]:
        return {
            "code": self.code,
            "weight": self.weight,
            "title": self.title,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class FoundURL:
    raw: str
    host: str
    text: str


def registrable(host: str) -> str:
    labels = [label for label in host.lower().rstrip(".").split(".") if label]
    if len(labels) < 2:
        return ".".join(labels)
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def decode_host(host: str) -> str:
    host = host.lower().rstrip(".")
    if "xn--" not in host:
        return host
    try:
        return host.encode("ascii").decode("idna")
    except UnicodeError:
        return host


def canon_label(label: str) -> str:
    folded = label.lower().translate(_CONFUSABLES)
    swapped = folded.replace("rn", "m")
    return swapped


def split_address(header: str) -> tuple[str, str, str]:
    name, address = parseaddr(header or "")
    address = address.strip().lower().rstrip(">")
    host = address.split("@", 1)[1] if "@" in address else ""
    return name.strip(), address, host.strip().rstrip(".")


def clean_url(url: str) -> str:
    url = url.strip().strip("<>")
    while url and url[-1] in _TRAILING:
        url = url[:-1]
    url = re.sub(r"(?i)^hxxps://", "https://", url)
    url = re.sub(r"(?i)^hxxp://", "http://", url)
    url = url.replace("[.]", ".").replace("(.)", ".")
    if url.startswith("//"):
        url = "http:" + url
    if url.lower().startswith("www."):
        url = "http://" + url
    return url


def host_of(url: str) -> str:
    cleaned = clean_url(url)
    if not cleaned or cleaned.lower().startswith(("mailto:", "javascript:", "data:")):
        return ""
    try:
        parsed = urlparse(cleaned)
    except ValueError:
        return ""
    return decode_host(parsed.hostname or "")


def is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def is_neutral_host(host: str) -> bool:
    return any(host == suffix or host.endswith("." + suffix) for suffix in _NEUTRAL_SUFFIXES)


def host_is_official(host: str, brand: Brand) -> bool:
    host = decode_host(host)
    if not host:
        return False
    if any(host == domain or host.endswith("." + domain) for domain in brand.official):
        return True
    registered = registrable(host)
    sld, _, tld = registered.partition(".")
    return bool(tld) and tld in _SAFE_TLDS and sld in brand.auto_names


def sender_is_known_official(host: str) -> bool:
    return any(host_is_official(host, brand) for brand in BRANDS)


def _contains_domain(host: str, domain: str) -> bool:
    labels = host.split(".")
    domain_labels = domain.split(".")
    width = len(domain_labels)
    if width == 0 or len(labels) <= width:
        return False
    for start in range(len(labels) - width):
        if labels[start : start + width] == domain_labels:
            return True
    return False


def _label_evokes(label: str, names: tuple[str, ...], mentioned: bool) -> bool:
    canon = canon_label(label)
    parts = [part for part in re.split(r"[^a-z]+", canon) if part]
    for name in names:
        if len(name) < 4:
            continue
        if canon == name or name in parts:
            others = [part for part in parts if part != name]
            if not others:
                if len(name) >= 6:
                    return True
                return mentioned
            if any(part in _LABEL_SUFFIXES for part in others):
                return True
            if mentioned and len(name) >= 5:
                return True
            continue
        for part in parts:
            if len(name) < 6:
                continue
            if part.startswith(name) and part[len(name) :] in _LABEL_SUFFIXES:
                return True
            if part.endswith(name) and part[: -len(name)] in {
                "secure",
                "login",
                "my",
                "account",
                "not",
                "the",
                "www",
            }:
                return True
    return False


def host_impersonates(host: str, brand: Brand, mentioned: bool) -> bool:
    host = decode_host(host)
    if not host or is_ip_host(host) or is_neutral_host(host) or host_is_official(host, brand):
        return False
    for domain in brand.official:
        if len(domain) >= 6 and _contains_domain(host, domain):
            return True
    return any(_label_evokes(label, brand.names, mentioned) for label in host.split("."))


def same_org(left: str, right: str) -> bool:
    if not left or not right:
        return False
    if left == right or left.endswith("." + right) or right.endswith("." + left):
        return True
    return registrable(left) == registrable(right)


def host_aligned(host: str, sender_host: str) -> bool:
    if same_org(host, sender_host):
        return True
    for brand in BRANDS:
        if host_is_official(sender_host, brand) and host_is_official(host, brand):
            return True
    return False


_BRAND_LABELS = {
    "paypal": "PayPal",
    "microsoft": "Microsoft",
    "apple": "Apple",
    "google": "Google",
    "amazon": "Amazon",
    "netflix": "Netflix",
    "github": "GitHub",
    "docusign": "DocuSign",
    "dropbox": "Dropbox",
    "linkedin": "LinkedIn",
    "facebook": "Facebook",
    "instagram": "Instagram",
    "whatsapp": "WhatsApp",
    "coinbase": "Coinbase",
    "binance": "Binance",
    "wellsfargo": "Wells Fargo",
    "bankofamerica": "Bank of America",
    "chase": "Chase",
    "fedex": "FedEx",
    "dhl": "DHL",
    "ups": "UPS",
    "irs": "IRS",
    "adobe": "Adobe",
}


def brand_label(brand: Brand) -> str:
    return _BRAND_LABELS.get(brand.key, brand.key)


def brands_mentioned(*chunks: str) -> set[str]:
    blob = "\n".join(chunk for chunk in chunks if chunk)
    found: set[str] = set()
    for brand in BRANDS:
        if brand.key == "ups":
            if re.search(r"\bups\b", blob, re.IGNORECASE) and re.search(
                r"\b(tracking|package|shipment|delivery|parcel)\b", blob, re.IGNORECASE
            ):
                found.add(brand.key)
            continue
        if brand.pattern.search(blob):
            found.add(brand.key)
    return found


def _scheme(url: str) -> str:
    cleaned = clean_url(url).lower()
    if cleaned.startswith("javascript:"):
        return "javascript"
    if cleaned.startswith("data:"):
        return "data"
    if cleaned.startswith("http://") or cleaned.startswith("https://"):
        return "http"
    return "other"


def _displayed_host(text: str) -> str:
    candidate = " ".join(text.split())
    if not candidate or len(candidate) > 200:
        return ""
    match = _URL_RE.search(candidate)
    if match and match.group(1) == candidate.strip():
        return host_of(candidate)
    bare = _BARE_HOST_RE.match(candidate.strip())
    if bare:
        return decode_host(bare.group(1))
    return ""


def collect_urls(parsed: ParsedEmail) -> list[FoundURL]:
    return _collect_urls(parsed)


def authentication_summary(parsed: ParsedEmail) -> dict[str, str]:
    """Read SPF, DKIM, and DMARC results written into the message headers."""
    blob = f"{parsed.authentication_results}\n{parsed.received_spf}"
    found: dict[str, str] = {}
    for match in re.finditer(
        r"(?i)\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|bestguesspass)",
        blob,
    ):
        kind = match.group(1).lower()
        if kind not in found:
            found[kind] = match.group(2).lower()
    return {
        "spf": found.get("spf", "none"),
        "dkim": found.get("dkim", "none"),
        "dmarc": found.get("dmarc", "none"),
    }


def _collect_urls(parsed: ParsedEmail) -> list[FoundURL]:
    found: list[FoundURL] = []
    seen: set[str] = set()
    # Anchor text often quotes a trustworthy URL. That string is evidence for
    # the mismatch check, not a second destination.
    displayed: set[str] = set()

    def add(raw: str, text: str) -> None:
        cleaned = raw.strip()
        if not cleaned or cleaned in seen:
            return
        seen.add(cleaned)
        found.append(FoundURL(raw=cleaned, host=host_of(cleaned), text=text.strip()))

    for link in parsed.links:
        add(link.href, link.text)
        shown = link.text.strip()
        if shown:
            displayed.add(shown)
            displayed.add(clean_url(shown))

    for match in _URL_RE.finditer(f"{parsed.subject}\n{parsed.text}"):
        raw = match.group(1)
        if raw.strip() in displayed or clean_url(raw) in displayed:
            continue
        add(raw, "")
    return found


def _join(items: list[str], limit: int = 3) -> str:
    shown = items[:limit]
    extra = len(items) - len(shown)
    text = "; ".join(shown)
    if extra > 0:
        text += f"; and {extra} more"
    return text


def _sentence(items: list[str]) -> str:
    text = _join(items)
    if not text:
        return text
    return text[0].upper() + text[1:] + "."


def _attachment_weight(filename: str) -> float:
    suffixes = [suffix.lower() for suffix in re.findall(r"\.[a-z0-9]+", filename.lower())]
    if any(suffix in _HIGH_RISK_EXTENSIONS for suffix in suffixes):
        return 2.3
    if any(suffix in _MED_RISK_EXTENSIONS for suffix in suffixes):
        return 1.6
    return 0.0


def _tld(host: str) -> str:
    registered = registrable(host)
    return registered.split(".", 1)[1] if "." in registered else ""


def extract_signals(parsed: ParsedEmail) -> list[Indicator]:
    display_name, sender_address, sender_host = split_address(parsed.from_header)
    _, reply_address, reply_host = split_address(parsed.reply_to)
    urls = collect_urls(parsed)
    http_urls = [url for url in urls if _scheme(url.raw) == "http" and url.host]
    mentioned = brands_mentioned(parsed.subject, parsed.text, display_name, *(url.text for url in urls))
    body = f"{parsed.subject}\n{parsed.text}"
    credential = bool(_CREDENTIAL_RE.search(body))
    urgency = bool(_URGENCY_RE.search(body))
    payment = bool(_PAYMENT_RE.search(body))
    secrecy = bool(_SECRECY_RE.search(body))
    indicators: list[Indicator] = []

    spoofed: list[str] = []
    for brand in BRANDS:
        brand_mentioned = brand.key in mentioned
        hosts: list[tuple[str, str]] = []
        if sender_host:
            hosts.append(("sender", sender_host))
        if reply_host:
            hosts.append(("reply-to address", reply_host))
        for url in http_urls:
            hosts.append(("link", url.host))
        for place, host in hosts:
            if host_impersonates(host, brand, brand_mentioned):
                spoofed.append(f"the {place} {host} imitates {brand_label(brand)}")
    if spoofed:
        indicators.append(
            Indicator(
                "brand_impersonation",
                2.1,
                "A domain imitates a known organization",
                _sentence(spoofed),
            )
        )

    mismatches: list[str] = []
    for url in urls:
        shown = _displayed_host(url.text)
        if shown and url.host and not same_org(shown, url.host):
            mismatches.append(f"the visible text points at {shown}, but the address goes to {url.host}")
    if mismatches:
        indicators.append(
            Indicator(
                "href_mismatch",
                2.2,
                "Link text does not match the destination",
                _sentence(mismatches),
            )
        )

    script_urls = [url.raw for url in urls if _scheme(url.raw) in {"javascript", "data"}]
    if script_urls:
        indicators.append(
            Indicator(
                "script_url",
                2.2,
                "A link runs script instead of opening a normal page",
                "Found " + _join(script_urls) + ".",
            )
        )

    ip_urls = [url.host for url in http_urls if is_ip_host(url.host)]
    if ip_urls:
        indicators.append(
            Indicator(
                "ip_url",
                2.0,
                "A link goes to a raw IP address",
                "Hosts: " + _join(ip_urls) + ".",
            )
        )

    at_urls: list[str] = []
    for url in urls:
        if _scheme(url.raw) != "http":
            continue
        try:
            parsed_url = urlparse(clean_url(url.raw))
        except ValueError:
            continue
        if parsed_url.username or "@" in (parsed_url.netloc or ""):
            at_urls.append(url.host or url.raw[:80])
    if at_urls:
        indicators.append(
            Indicator(
                "at_sign_url",
                1.8,
                "A link hides its real host behind an @ sign",
                "The destination host is " + _join(at_urls) + ".",
            )
        )

    if parsed.has_password_field:
        indicators.append(
            Indicator(
                "password_form",
                2.4,
                "The message contains a password field",
                "Asking for a password inside an email is a credential-harvest pattern.",
            )
        )

    risky_files = [item.filename or item.content_type for item in parsed.attachments if _attachment_weight(item.filename) > 0]
    if risky_files:
        weight = max(_attachment_weight(item.filename) for item in parsed.attachments)
        indicators.append(
            Indicator(
                "risky_attachment",
                weight,
                "An attachment is a type often used in phishing",
                "Files: " + _join(risky_files) + ".",
            )
        )

    display_hits: list[str] = []
    for brand in BRANDS:
        if brand.key not in brands_mentioned(display_name):
            continue
        if sender_host and not host_is_official(sender_host, brand):
            display_hits.append(
                f"{display_name or brand_label(brand)} is not sent from a {brand_label(brand)} domain ({sender_address or 'unknown sender'})"
            )
    if display_hits and sender_host:
        indicators.append(
            Indicator(
                "display_name_impersonation",
                1.8,
                "The display name claims an organization the address does not belong to",
                _join(display_hits) + ".",
            )
        )

    embedded = _EMBEDDED_ADDRESS.findall(display_name)
    if embedded and sender_address and embedded[0].lower() != sender_address:
        indicators.append(
            Indicator(
                "display_name_address_mismatch",
                1.7,
                "The display name contains a different email address",
                f"The name shows {embedded[0]}, but the real address is {sender_address}.",
            )
        )

    if (
        reply_host
        and sender_host
        and registrable(reply_host) != registrable(sender_host)
        and not any(
            host_is_official(sender_host, brand) and host_is_official(reply_host, brand) for brand in BRANDS
        )
    ):
        indicators.append(
            Indicator(
                "reply_to_mismatch",
                0.8,
                "Replies would go to a different domain",
                f"From is {sender_host}, but Reply-To is {reply_host}.",
            )
        )

    suspicious_hosts = [
        url.host
        for url in http_urls
        if _tld(url.host) in _SUSPICIOUS_TLDS and (mentioned or credential or urgency)
    ]
    if reply_host and _tld(reply_host) in _SUSPICIOUS_TLDS and (mentioned or credential or urgency):
        suspicious_hosts.append(reply_host)
    if suspicious_hosts:
        indicators.append(
            Indicator(
                "suspicious_tld",
                1.3,
                "A domain uses a TLD that shows up often in phishing",
                "Hosts: " + _join(suspicious_hosts) + ".",
            )
        )

    short_hosts = [url.host for url in http_urls if registrable(url.host) in _SHORTENERS or url.host in _SHORTENERS]
    if short_hosts and (credential or urgency or payment):
        indicators.append(
            Indicator(
                "shortener_lure",
                1.2,
                "A shortened link is paired with a request that needs care",
                "Short links hide the destination. Hosts: " + _join(short_hosts) + ".",
            )
        )

    external = [url.host for url in http_urls if not sender_host or not host_aligned(url.host, sender_host)]
    if credential and urgency and external:
        indicators.append(
            Indicator(
                "pressure_external_link",
                1.2,
                "Urgency, a credential request, and an outside link appear together",
                "The message pressures the reader and sends them to " + _join(external) + ".",
            )
        )

    sender_registered = registrable(sender_host) if sender_host else ""
    if sender_registered in _FREEMAIL and payment:
        if _EXEC_RE.search(display_name) or secrecy:
            pay_weight = 1.7
            pay_detail = "A free mailbox is asking for a payment or banking change, with secrecy or an executive title."
        elif urgency:
            pay_weight = 1.1
            pay_detail = "A free mailbox is asking for a payment and pushing for speed."
        else:
            pay_weight = 0.5
            pay_detail = "A free mailbox mentions a payment or banking change."
        indicators.append(
            Indicator(
                "freemail_payment",
                pay_weight,
                "Payment request comes from free webmail",
                f"{sender_address} is on {sender_registered}. {pay_detail}",
            )
        )

    aligned = bool(http_urls) and bool(sender_host) and all(host_aligned(url.host, sender_host) for url in http_urls)
    impersonated = any(item.code == "brand_impersonation" for item in indicators)
    if aligned and not impersonated:
        if sender_is_known_official(sender_host):
            indicators.append(
                Indicator(
                    "links_match_known_sender",
                    -1.8,
                    "Links stay on the sender's organization",
                    f"Every link matches {sender_host}, which is a known domain for that organization.",
                )
            )
        else:
            indicators.append(
                Indicator(
                    "links_match_sender",
                    -0.35,
                    "Links use the same domain as the sender",
                    f"Links and the From address both use {registrable(sender_host)}. That is only weak evidence, because a new domain can still be phishing.",
                )
            )

    auth = authentication_summary(parsed)
    if auth["dmarc"] == "fail":
        indicators.append(
            Indicator(
                "dmarc_fail",
                1.5,
                "DMARC failed",
                "The pasted Authentication-Results header says DMARC failed. Trust that when your mail server added the header, not when the sender wrote it.",
            )
        )
    if auth["spf"] == "fail":
        indicators.append(
            Indicator(
                "spf_fail",
                1.2,
                "SPF failed",
                "The pasted headers say SPF failed for this sender.",
            )
        )
    if auth["dkim"] == "fail":
        indicators.append(
            Indicator(
                "dkim_fail",
                0.9,
                "DKIM failed",
                "The pasted headers say the DKIM signature did not verify.",
            )
        )

    indicators.sort(key=lambda item: item.weight, reverse=True)
    return indicators
