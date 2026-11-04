"""Domain age, header context, and existing urlscan / VirusTotal reports.

Lookups send only a domain or URL that was already in the message. They go to
rdap.org, www.virustotal.com, and urlscan.io. A missing RDAP record is not
treated as a newly registered domain, and urlscan's own age field is ignored.
Nothing here submits a URL for a new live scan.
"""

from __future__ import annotations

import base64
import copy
import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

from phishdet.detect import detect, with_extra
from phishdet.parse import ParsedEmail, parse_email
from phishdet.signals import (
    Indicator,
    authentication_summary,
    clean_url,
    collect_urls,
    is_ip_host,
    registrable,
    split_address,
)

_ALLOWED_HOSTS = frozenset({"rdap.org", "www.virustotal.com", "urlscan.io"})
_ENV_KEYS = ("VIRUSTOTAL_API_KEY", "URLSCAN_API_KEY")
_RESERVED_TLDS = frozenset({
    "example",
    "invalid",
    "test",
    "local",
    "localhost",
    "internal",
    "home",
    "lan",
    "localdomain",
    "arpa",
})
_RESERVED_DOMAINS = frozenset({"example.com", "example.net", "example.org"})
_DOMAIN_RE = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
)
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_USER_AGENT = "phishdet"
_TIMEOUT = 8
_CACHE_TTL = 600
_ERROR_TTL = 45
_MAX_DOMAINS = 4
_MAX_URL_LOOKUPS = 3
_YOUNG_DAYS = 14
_RECENT_DAYS = 90

_CACHE: dict[str, tuple[float, dict]] = {}
_CACHE_LOCK = threading.Lock()
_ENV_LOADED = False
_ENV_LOCK = threading.Lock()


def clear_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()


def load_env() -> None:
    """Load the two provider keys from a project .env when the environment lacks them."""
    global _ENV_LOADED
    with _ENV_LOCK:
        if _ENV_LOADED:
            return
        _ENV_LOADED = True
    for path in (_project_env(), Path.cwd() / ".env"):
        _apply_env_file(path)


def service_status() -> dict[str, bool]:
    load_env()
    return {
        "rdap": True,
        "virustotal": bool(os.environ.get("VIRUSTOTAL_API_KEY")),
        "urlscan": True,
        "urlscan_key": bool(os.environ.get("URLSCAN_API_KEY")),
    }


def public_domain(host: str) -> str:
    """Registrable domain worth a public lookup, or an empty string."""
    host = (host or "").strip().lower().rstrip(".")
    if not host or is_ip_host(host) or host in {"localhost", "localhost.localdomain"}:
        return ""
    if any(not label or len(label) > 63 for label in host.split(".")):
        return ""
    registered = registrable(host)
    if "." not in registered:
        return ""
    tld = registered.rsplit(".", 1)[-1]
    if tld in _RESERVED_TLDS or tld.isdigit() or registered in _RESERVED_DOMAINS:
        return ""
    try:
        ascii_domain = registered.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    if not _DOMAIN_RE.fullmatch(ascii_domain):
        return ""
    return ascii_domain


def age_from_rdap(payload: dict) -> dict[str, str]:
    registered = ""
    expires = ""
    events = payload.get("events") if isinstance(payload, dict) else None
    if isinstance(events, list):
        for event in events:
            if not isinstance(event, dict):
                continue
            action = str(event.get("eventAction") or "").lower()
            date = str(event.get("eventDate") or "")
            if not date:
                continue
            if action in {"registration", "registered"} and not registered:
                registered = date
            elif action in {"expiration", "registrar expiration", "expiry"} and not expires:
                expires = date
    return {"registered": registered, "expires": expires}


def age_days(value: str, now: datetime | None = None) -> int | None:
    stamp = _parse_time(value)
    if stamp is None:
        return None
    moment = now or datetime.now(timezone.utc)
    if stamp > moment or stamp.year < 1985:
        return None
    return (moment.date() - stamp.date()).days


def vt_from_domain(payload: dict) -> dict:
    attributes = _vt_attributes(payload)
    stats = attributes.get("last_analysis_stats")
    if not isinstance(stats, dict):
        stats = {}
    created = attributes.get("creation_date")
    if isinstance(created, bool) or not isinstance(created, int):
        created = None
    return {
        "malicious": _count(stats.get("malicious")),
        "suspicious": _count(stats.get("suspicious")),
        "harmless": _count(stats.get("harmless")),
        "undetected": _count(stats.get("undetected")),
        "creation_date": created,
    }


def vt_from_url(payload: dict) -> dict:
    parsed = vt_from_domain(payload)
    parsed.pop("creation_date", None)
    return parsed


def urlscan_from_search(payload: dict, domain: str) -> dict:
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list) or not results:
        return _scan_result("none", None, "", "No public urlscan report.")
    matching: list[dict] = []
    saw_other = False
    for item in results:
        if not isinstance(item, dict):
            continue
        relation = _scan_relation(item, domain)
        if relation == "match":
            matching.append(item)
        elif relation == "unrelated":
            saw_other = True
    if not matching:
        if saw_other:
            return _scan_result(
                "unrelated",
                None,
                "",
                "A public scan exists for a different host. It was not used as a verdict.",
            )
        return _scan_result("none", None, "", "No public urlscan report.")
    chosen = matching[0]
    malicious: bool | None = None
    for item in matching:
        flag = _scan_flag(item)
        if flag is True:
            chosen = item
            malicious = True
            break
        if flag is False and malicious is None:
            chosen = item
            malicious = False
    uuid = _scan_uuid(chosen)
    link = f"https://urlscan.io/result/{uuid}/" if uuid else ""
    if malicious is True:
        return _scan_result("malicious", True, link, "urlscan marked a matching public scan as malicious.", uuid)
    if malicious is False:
        return _scan_result("clean", False, link, "A matching public scan is not marked malicious.", uuid)
    return _scan_result(
        "seen",
        None,
        link,
        "A public scan exists. That alone is not a malicious verdict.",
        uuid,
    )


def header_report(parsed: ParsedEmail) -> dict:
    auth = authentication_summary(parsed)
    notes: list[dict[str, str]] = []
    if not parsed.is_raw_email:
        notes.append({
            "title": "No mail headers",
            "detail": "This was pasted as message text, so SPF, DKIM, DMARC, and the From line were not available.",
        })
    else:
        _, _, sender_host = split_address(parsed.from_header)
        _, _, return_host = split_address(parsed.return_path)
        if return_host and sender_host and registrable(return_host) != registrable(sender_host):
            notes.append({
                "title": "Return-Path uses a different domain",
                "detail": (
                    f"Return-Path is {return_host} and From is {sender_host}. "
                    "Mailing lists and providers do this. It is not scored."
                ),
            })
        mid_host = _message_id_host(parsed.message_id)
        sender_domain = public_domain(sender_host)
        mid_domain = public_domain(mid_host)
        if sender_domain and mid_domain and sender_domain != mid_domain:
            notes.append({
                "title": "Message-ID domain differs from From",
                "detail": (
                    f"Message-ID uses {mid_host} and From uses {sender_host}. "
                    "Mail systems often do this, so it is only context."
                ),
            })
        if parsed.has_dkim_signature and auth["dkim"] == "none":
            notes.append({
                "title": "DKIM signature present, no result",
                "detail": "The message includes a DKIM-Signature header, but the pasted Authentication-Results do not say whether it verified.",
            })
        if (
            auth["spf"] == "none"
            and auth["dkim"] == "none"
            and auth["dmarc"] == "none"
            and not parsed.authentication_results
            and not parsed.received_spf
        ):
            notes.append({
                "title": "No authentication results",
                "detail": "The paste has no Authentication-Results or Received-SPF header. A sender can forge those headers. Trust them when your mail server added them.",
            })
    return {
        "from": parsed.from_header,
        "reply_to": parsed.reply_to,
        "return_path": parsed.return_path,
        "message_id": parsed.message_id,
        "date": parsed.date,
        "spf": auth["spf"],
        "dkim": auth["dkim"],
        "dmarc": auth["dmarc"],
        "dkim_signature_present": parsed.has_dkim_signature,
        "is_raw_email": parsed.is_raw_email,
        "notes": notes,
    }


def resources_from(parsed: ParsedEmail) -> list[dict]:
    grouped: dict[str, dict] = {}

    def add(domain: str, role: str, url: str = "") -> None:
        if not domain:
            return
        slot = grouped.get(domain)
        if slot is None:
            if len(grouped) >= 8:
                return
            slot = {"domain": domain, "roles": [], "urls": []}
            grouped[domain] = slot
        if role not in slot["roles"]:
            slot["roles"].append(role)
        if url and url not in slot["urls"] and len(slot["urls"]) < 3:
            slot["urls"].append(url[:500])

    _, _, sender_host = split_address(parsed.from_header)
    add(public_domain(sender_host), "sender")
    _, _, reply_host = split_address(parsed.reply_to)
    add(public_domain(reply_host), "reply-to")
    for found in collect_urls(parsed):
        cleaned = clean_url(found.raw)
        if not found.host or not cleaned.lower().startswith(("http://", "https://")):
            continue
        add(public_domain(found.host), "link", cleaned)
    return list(grouped.values())


def local_view(raw: str | bytes) -> dict:
    load_env()
    verdict = detect(raw)
    parsed = parse_email(raw)
    payload = verdict.to_dict()
    payload["headers"] = header_report(parsed)
    payload["resources"] = [_pending(item) for item in resources_from(parsed)]
    payload["intel"] = {"status": "pending", "services": service_status(), "looked_up": 0, "total": len(payload["resources"])}
    return payload


def investigate(raw: str | bytes) -> dict:
    load_env()
    verdict = detect(raw)
    parsed = parse_email(raw)
    resources = resources_from(parsed)
    reports = _look_up(resources)
    updated = with_extra(verdict, external_indicators(reports))
    payload = updated.to_dict()
    payload["headers"] = header_report(parsed)
    payload["resources"] = reports
    payload["intel"] = {
        "status": "done",
        "services": service_status(),
        "looked_up": min(_MAX_DOMAINS, len(resources)),
        "total": len(resources),
    }
    return payload


def external_indicators(reports: list[dict]) -> list[Indicator]:
    indicators: list[Indicator] = []
    seen: set[str] = set()
    for report in reports:
        if not isinstance(report, dict):
            continue
        domain = str(report.get("domain") or "")
        if not domain or domain in seen:
            continue
        seen.add(domain)
        age = report.get("age_days")
        if isinstance(age, int) and age >= 0:
            registered = str(report.get("registered") or "")[:10]
            when = f" on {registered}" if registered else ""
            if age < _YOUNG_DAYS:
                indicators.append(Indicator(
                    "young_domain",
                    1.6,
                    "Domain was registered recently",
                    f"{domain} was registered {age} days ago{when}. New domains are common in phishing.",
                ))
            elif age < _RECENT_DAYS:
                indicators.append(Indicator(
                    "recent_domain",
                    0.9,
                    "Domain is less than 90 days old",
                    f"{domain} was registered {age} days ago{when}.",
                ))
        malicious = _highest_count(report.get("vt_malicious"), report.get("vt_url_malicious"))
        if malicious is not None and malicious >= 1:
            indicators.append(Indicator(
                "virustotal_malicious",
                2.0,
                "VirusTotal engines flagged this domain",
                f"{malicious} engines marked {domain} as malicious.",
            ))
        if report.get("urlscan_malicious") is True:
            indicators.append(Indicator(
                "urlscan_malicious",
                1.8,
                "urlscan marked a public scan as malicious",
                f"A public urlscan result for {domain} is marked malicious.",
            ))
    return indicators


def lookup_domain(domain: str, urls: list[str] | None = None, include_url: bool = False) -> dict:
    load_env()
    checked = public_domain(domain)
    if not checked:
        report = _blank(domain)
        report["age_status"] = "skipped"
        report["age_detail"] = "Not a public domain."
        report["vt_status"] = "skipped"
        report["vt_detail"] = "Not a public domain."
        report["urlscan_status"] = "skipped"
        report["urlscan_detail"] = "Not a public domain."
        report["vt_link"] = ""
        return report
    report = _blank(checked)
    chosen_urls = [url for url in (urls or []) if isinstance(url, str) and url.lower().startswith(("http://", "https://"))]
    chosen_urls = [url for url in chosen_urls if len(url) <= 512][:1]
    jobs: dict[str, object] = {
        "rdap": lambda: _cached(f"rdap:{checked}", lambda: _rdap(checked)),
        "vt": lambda: _cached(f"vt:{checked}", lambda: _vt_domain(checked)),
        "scan": lambda: _cached(f"scan:{checked}", lambda: _urlscan(checked)),
    }
    if include_url and chosen_urls:
        url = chosen_urls[0]
        jobs["vturl"] = lambda url=url: _cached(f"vturl:{url}", lambda: _vt_url(url))
    found: dict[str, dict | None] = {}
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = {name: pool.submit(job) for name, job in jobs.items()}
        for name, future in futures.items():
            try:
                found[name] = future.result(timeout=14)
            except Exception:
                found[name] = None
    _apply_rdap(report, found.get("rdap"))
    if report["age_status"] != "registered":
        created = (found.get("vt") or {}).get("creation_date") if isinstance(found.get("vt"), dict) else None
        if isinstance(created, int):
            _apply_unix_creation(report, created)
    _apply_vt(report, found.get("vt"), found.get("vturl"), include_url and bool(chosen_urls))
    _apply_scan(report, found.get("scan"))
    return report


def _look_up(resources: list[dict]) -> list[dict]:
    selected = resources[:_MAX_DOMAINS]
    url_budget = _MAX_URL_LOOKUPS
    jobs: list[tuple[dict, bool]] = []
    for resource in selected:
        include_url = bool(resource["urls"]) and url_budget > 0
        if include_url:
            url_budget -= 1
        jobs.append((resource, include_url))
    reports: list[dict] = []
    if jobs:
        with ThreadPoolExecutor(max_workers=min(4, len(jobs))) as pool:
            futures = [
                pool.submit(lookup_domain, resource["domain"], resource["urls"], include_url)
                for resource, include_url in jobs
            ]
            for resource, future in zip((item[0] for item in jobs), futures):
                try:
                    report = future.result(timeout=20)
                except Exception:
                    report = _blank(resource["domain"])
                    report["age_status"] = "unavailable"
                    report["age_detail"] = "Domain age lookup did not finish."
                    report["vt_status"] = "error"
                    report["vt_detail"] = "VirusTotal did not finish."
                    report["urlscan_status"] = "error"
                    report["urlscan_detail"] = "urlscan did not finish."
                report["roles"] = list(resource["roles"])
                report["urls"] = list(resource["urls"])
                reports.append(report)
    for resource in resources[_MAX_DOMAINS:]:
        reports.append(_capped(resource))
    return reports


def _apply_rdap(report: dict, parsed: dict | None) -> None:
    if not parsed:
        report["age_status"] = "unavailable"
        report["age_detail"] = "Domain age lookup did not respond."
        return
    status = parsed.get("status")
    if status == "no_record":
        report["age_status"] = "no_record"
        report["age_detail"] = "No RDAP registration record. That is not treated as a new domain."
        return
    if status != "registered":
        report["age_status"] = "unavailable"
        report["age_detail"] = "Domain age lookup did not respond."
        return
    registered = str(parsed.get("registered") or "")
    days = age_days(registered)
    if days is None:
        report["age_status"] = "no_record"
        report["age_detail"] = "RDAP responded but did not include a registration date. That is not treated as a new domain."
        return
    report["age_status"] = "registered"
    report["age_source"] = "rdap"
    report["registered"] = registered
    report["expires"] = str(parsed.get("expires") or "")
    report["age_days"] = days
    report["age_detail"] = _format_age(registered[:10], days, "rdap")


def _apply_unix_creation(report: dict, created: int) -> None:
    if created <= 0:
        return
    try:
        stamp = datetime.fromtimestamp(created, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return
    days = age_days(stamp.isoformat())
    if days is None:
        return
    report["age_status"] = "registered"
    report["age_source"] = "virustotal"
    report["registered"] = stamp.date().isoformat()
    report["age_days"] = days
    report["age_detail"] = _format_age(stamp.date().isoformat(), days, "virustotal")


def _apply_vt(report: dict, domain_info: dict | None, url_info: dict | None, looked_up_url: bool) -> None:
    if not os.environ.get("VIRUSTOTAL_API_KEY"):
        report["vt_status"] = "unconfigured"
        report["vt_detail"] = "VirusTotal key is not set."
        report["vt_url_status"] = "unconfigured"
        return
    if not isinstance(domain_info, dict):
        report["vt_status"] = "error"
        report["vt_detail"] = "VirusTotal did not respond."
    else:
        report["vt_status"] = domain_info.get("status") or "error"
        report["vt_malicious"] = domain_info.get("malicious")
        report["vt_suspicious"] = domain_info.get("suspicious")
        report["vt_harmless"] = domain_info.get("harmless")
        report["vt_undetected"] = domain_info.get("undetected")
        report["vt_detail"] = domain_info.get("detail") or "VirusTotal did not respond."
    if not looked_up_url:
        report["vt_url_status"] = "skipped"
        return
    if not isinstance(url_info, dict):
        report["vt_url_status"] = "error"
        return
    report["vt_url_status"] = url_info.get("status") or "error"
    report["vt_url_malicious"] = url_info.get("malicious")
    if url_info.get("status") == "malicious" and report["vt_status"] != "malicious":
        report["vt_detail"] = url_info.get("detail") or report["vt_detail"]
    elif url_info.get("status") == "no_report":
        extra = " No VirusTotal report for the URL. It was not submitted."
        if extra.strip() not in report["vt_detail"]:
            report["vt_detail"] = (report["vt_detail"] + extra).strip()


def _apply_scan(report: dict, parsed: dict | None) -> None:
    if not isinstance(parsed, dict):
        report["urlscan_status"] = "error"
        report["urlscan_detail"] = "urlscan did not respond."
        return
    report["urlscan_status"] = parsed.get("status") or "error"
    report["urlscan_malicious"] = parsed.get("malicious")
    report["urlscan_link"] = parsed.get("link") or ""
    report["urlscan_detail"] = parsed.get("detail") or "urlscan did not respond."


def _rdap(domain: str) -> dict:
    status, payload = _request_json(
        f"https://rdap.org/domain/{urllib.parse.quote(domain)}",
        allow_redirect_hosts=None,
    )
    if status == 404:
        return {"status": "no_record", "registered": "", "expires": ""}
    if status != 200 or not isinstance(payload, dict):
        return {"status": "unavailable", "registered": "", "expires": ""}
    parsed = age_from_rdap(payload)
    if not parsed["registered"]:
        return {"status": "no_record", "registered": "", "expires": parsed["expires"]}
    return {"status": "registered", "registered": parsed["registered"], "expires": parsed["expires"]}


def _vt_domain(domain: str) -> dict:
    key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not key:
        return {"status": "unconfigured", "detail": "VirusTotal key is not set.", "malicious": None}
    status, payload = _request_json(
        f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain)}",
        headers={"x-apikey": key},
        allow_redirect_hosts={"www.virustotal.com"},
    )
    return _vt_status(status, payload, kind="domain")


def _vt_url(url: str) -> dict:
    key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not key:
        return {"status": "unconfigured", "detail": "VirusTotal key is not set.", "malicious": None}
    token = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    status, payload = _request_json(
        f"https://www.virustotal.com/api/v3/urls/{token}",
        headers={"x-apikey": key},
        allow_redirect_hosts={"www.virustotal.com"},
    )
    parsed = _vt_status(status, payload, kind="url")
    if parsed["status"] == "no_report":
        parsed["detail"] = "No VirusTotal report for the URL. It was not submitted."
    return parsed


def _vt_status(status: int, payload: dict | None, kind: str) -> dict:
    if status == 404:
        return {"status": "no_report", "detail": f"No VirusTotal report for this {kind}.", "malicious": None}
    if status == 401:
        return {"status": "rejected", "detail": "VirusTotal rejected the API key.", "malicious": None}
    if status == 429:
        return {"status": "rate_limited", "detail": "VirusTotal rate limited this lookup.", "malicious": None}
    if status != 200 or not isinstance(payload, dict):
        return {"status": "error", "detail": "VirusTotal did not respond.", "malicious": None}
    parsed = vt_from_domain(payload) if kind == "domain" else vt_from_url(payload)
    malicious = parsed.get("malicious")
    detail = _vt_detail(parsed)
    if malicious is None:
        state = "unknown"
    elif malicious >= 1:
        state = "malicious"
    else:
        state = "clean"
    parsed["status"] = state
    parsed["detail"] = detail
    return parsed


def _urlscan(domain: str) -> dict:
    query = urllib.parse.urlencode({"q": f"domain:{domain}", "size": "5"})
    headers = {}
    key = os.environ.get("URLSCAN_API_KEY", "")
    if key:
        headers["API-Key"] = key
    status, payload = _request_json(
        f"https://urlscan.io/api/v1/search/?{query}",
        headers=headers,
        allow_redirect_hosts={"urlscan.io"},
    )
    if status == 429:
        return _scan_result("rate_limited", None, "", "urlscan rate limited this lookup. An API key raises the limit.")
    if status == 401:
        return _scan_result("rejected", None, "", "urlscan rejected the API key.")
    if status != 200 or not isinstance(payload, dict):
        return _scan_result("error", None, "", "urlscan did not respond.")
    parsed = urlscan_from_search(payload, domain)
    if parsed["status"] == "seen" and parsed.get("uuid"):
        extra = _urlscan_result(str(parsed["uuid"]))
        if extra and extra.get("malicious") is True:
            parsed["status"] = "malicious"
            parsed["malicious"] = True
            parsed["detail"] = "urlscan marked a matching public scan as malicious."
        elif extra and extra.get("malicious") is False:
            parsed["status"] = "clean"
            parsed["malicious"] = False
            parsed["detail"] = "A matching public scan is not marked malicious."
    return parsed


def _urlscan_result(uuid: str) -> dict | None:
    if not _UUID_RE.fullmatch(uuid):
        return None
    headers = {}
    key = os.environ.get("URLSCAN_API_KEY", "")
    if key:
        headers["API-Key"] = key
    status, payload = _request_json(
        f"https://urlscan.io/api/v1/result/{uuid}/",
        headers=headers,
        allow_redirect_hosts={"urlscan.io"},
    )
    if status != 200 or not isinstance(payload, dict):
        return None
    flag = _scan_flag(payload)
    if flag is None:
        return None
    return {"malicious": flag}


def _decode_json(raw: bytes) -> dict | None:
    if not raw:
        return None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _request_json(
    url: str,
    headers: dict[str, str] | None = None,
    allow_redirect_hosts: set[str] | None = None,
) -> tuple[int, dict | None]:
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or host not in _ALLOWED_HOSTS:
        return 0, None
    if not _addresses_are_public(host):
        return 0, None
    request = urllib.request.Request(
        url,
        headers={"User-Agent": _USER_AGENT, "Accept": "application/json", **(headers or {})},
    )
    opener = urllib.request.build_opener(_SafeRedirect(allow_redirect_hosts))
    try:
        with opener.open(request, timeout=_TIMEOUT) as response:
            return response.status, _decode_json(response.read(1_000_000))
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(200_000)
        except Exception:
            body = b""
        return exc.code, _decode_json(body)
    except (urllib.error.URLError, TimeoutError, OSError, socket.timeout):
        return 0, None


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: set[str] | None) -> None:
        super().__init__()
        self.allowed_hosts = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or not _addresses_are_public(host):
            raise urllib.error.URLError("refusing redirect")
        if self.allowed_hosts is not None and host not in self.allowed_hosts:
            raise urllib.error.URLError("refusing redirect host")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None:
            for name in ("x-apikey", "Authorization", "API-Key"):
                redirected.remove_header(name)
        return redirected


def _addresses_are_public(host: str) -> bool:
    if not host or host in {"localhost", "localhost.localdomain"}:
        return False
    if is_ip_host(host):
        try:
            return ipaddress.ip_address(host).is_global
        except ValueError:
            return False
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    if not infos:
        return False
    for info in infos:
        address = info[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if not ip.is_global:
            return False
    return True


def _cached(key: str, loader) -> dict:
    now = time.monotonic()
    with _CACHE_LOCK:
        hit = _CACHE.get(key)
        if hit and hit[0] > now:
            return copy.deepcopy(hit[1])
    value = loader()
    if value.get("status") == "unconfigured":
        return copy.deepcopy(value)
    ttl = _ERROR_TTL if value.get("status") in {"error", "unavailable", "rate_limited", "rejected"} else _CACHE_TTL
    with _CACHE_LOCK:
        _CACHE[key] = (time.monotonic() + ttl, value)
    return copy.deepcopy(value)


def _blank(domain: str) -> dict:
    link = ""
    if domain and _DOMAIN_RE.fullmatch(domain):
        link = f"https://www.virustotal.com/gui/domain/{domain}"
    return {
        "domain": domain,
        "roles": [],
        "urls": [],
        "age_days": None,
        "registered": "",
        "expires": "",
        "age_source": "",
        "age_status": "pending",
        "age_detail": "",
        "vt_status": "pending",
        "vt_malicious": None,
        "vt_suspicious": None,
        "vt_harmless": None,
        "vt_undetected": None,
        "vt_url_status": "pending",
        "vt_url_malicious": None,
        "vt_link": link,
        "vt_detail": "",
        "urlscan_status": "pending",
        "urlscan_malicious": None,
        "urlscan_link": "",
        "urlscan_detail": "",
    }


def _pending(resource: dict) -> dict:
    report = _blank(resource["domain"])
    report["roles"] = list(resource["roles"])
    report["urls"] = list(resource["urls"])
    report["age_detail"] = "Checking registration date…"
    report["vt_detail"] = "Checking VirusTotal…"
    report["urlscan_detail"] = "Checking urlscan…"
    return report


def _capped(resource: dict) -> dict:
    report = _blank(resource["domain"])
    report["roles"] = list(resource["roles"])
    report["urls"] = list(resource["urls"])
    report["age_status"] = "skipped"
    report["vt_status"] = "skipped"
    report["urlscan_status"] = "skipped"
    report["vt_url_status"] = "skipped"
    note = "Lookup limit reached for this message."
    report["age_detail"] = note
    report["vt_detail"] = note
    report["urlscan_detail"] = note
    return report


def _format_age(day: str, days: int, source: str) -> str:
    noun = "day" if days == 1 else "days"
    via = "RDAP" if source == "rdap" else "VirusTotal"
    return f"Registered {day} ({days} {noun} ago) via {via}."


def _vt_detail(parsed: dict) -> str:
    parts = []
    for label, key in (
        ("malicious", "malicious"),
        ("suspicious", "suspicious"),
        ("harmless", "harmless"),
        ("undetected", "undetected"),
    ):
        value = parsed.get(key)
        if isinstance(value, int):
            parts.append(f"{value} {label}")
    if not parts:
        return "VirusTotal returned no engine counts."
    return "VirusTotal: " + ", ".join(parts) + "."


def _scan_result(status: str, malicious: bool | None, link: str, detail: str, uuid: str = "") -> dict:
    return {"status": status, "malicious": malicious, "link": link, "detail": detail, "uuid": uuid}


def _scan_relation(item: dict, domain: str) -> str:
    task = item.get("task") if isinstance(item.get("task"), dict) else {}
    page = item.get("page") if isinstance(item.get("page"), dict) else {}
    task_domain = str(task.get("domain") or "").lower().rstrip(".")
    page_domain = str(page.get("domain") or "").lower().rstrip(".")

    def under(host: str) -> bool:
        return bool(host) and (host == domain or host.endswith("." + domain))

    if not task_domain and not page_domain:
        return "unknown"
    if under(task_domain) and (not page_domain or under(page_domain)):
        return "match"
    return "unrelated"


def _scan_flag(item: dict) -> bool | None:
    verdicts = item.get("verdicts")
    if not isinstance(verdicts, dict):
        return None
    overall = verdicts.get("overall")
    if not isinstance(overall, dict) or "malicious" not in overall:
        return None
    flag = overall.get("malicious")
    if flag is True:
        return True
    if flag is False:
        return False
    return None


def _scan_uuid(item: dict) -> str:
    task = item.get("task") if isinstance(item.get("task"), dict) else {}
    for candidate in (item.get("_id"), task.get("uuid")):
        text = str(candidate or "")
        if _UUID_RE.fullmatch(text):
            return text
    return ""


def _vt_attributes(payload: dict) -> dict:
    if not isinstance(payload, dict):
        return {}
    data = payload.get("data")
    if isinstance(data, dict) and isinstance(data.get("attributes"), dict):
        return data["attributes"]
    return {}


def _count(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _highest_count(*values: object) -> int | None:
    numbers = [value for value in values if isinstance(value, int)]
    if not numbers:
        return None
    return max(numbers)


def _parse_time(value: str) -> datetime | None:
    text = (value or "").strip()
    if not text:
        return None
    try:
        stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            stamp = parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError, OverflowError):
            return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc)


def _message_id_host(value: str) -> str:
    match = re.search(r"@([A-Za-z0-9.-]+)>?\s*$", value or "")
    return match.group(1).lower().rstrip(".") if match else ""


def _project_env() -> Path:
    return Path(__file__).resolve().parents[2] / ".env"


def _apply_env_file(path: Path) -> None:
    if not path.is_file():
        return
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        if key not in _ENV_KEYS or key in os.environ:
            continue
        value = value.strip().strip('"').strip("'")
        if value:
            os.environ[key] = value
