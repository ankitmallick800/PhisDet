"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path

from phishdet.detect import Verdict, detect
from phishdet.intel import header_report, investigate
from phishdet.parse import parse_email
from phishdet.signals import Indicator

SAMPLE_DIR = Path(__file__).resolve().parent / "samples"
SAMPLES = {
    "phishing": "phishing.eml",
    "legitimate": "legitimate.eml",
    "reset": "reset.eml",
    "bec": "bec.eml",
}


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.command == "serve":
        from phishdet.server import serve

        serve(args.host, args.port)
        return 0
    try:
        raw = _read_input(args)
        if args.intel:
            report = investigate(raw)
        else:
            report = None
            verdict = detect(raw)
    except (OSError, ValueError, FileNotFoundError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if args.intel:
        if args.json:
            json.dump(report, sys.stdout, indent=2)
            sys.stdout.write("\n")
        else:
            _print_human(_verdict_from_report(report), color=sys.stdout.isatty() and not args.no_color)
            _print_headers(report["headers"])
            _print_resources(report["resources"])
        return 0
    if args.json:
        json.dump(verdict.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        _print_human(verdict, color=sys.stdout.isatty() and not args.no_color)
        _print_headers(header_report(parse_email(raw)))
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="phishdet",
        description="Decide whether an email is phishing.",
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Check one email")
    scan.add_argument("path", nargs="?", help="Path to an .eml or text file, or - for stdin")
    scan.add_argument("--sample", choices=sorted(SAMPLES), help="Check a built-in example")
    scan.add_argument("--json", action="store_true", help="Print the verdict as JSON")
    scan.add_argument("--no-color", action="store_true", help="Do not color the verdict")
    scan.add_argument(
        "--intel",
        action="store_true",
        help="Also look up domain age, urlscan, and VirusTotal for hosts in the message",
    )

    serve = sub.add_parser("serve", help="Open a local page to paste an email")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)

    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] not in {"scan", "serve", "-h", "--help"}:
        raw = ["scan", *raw]
    args = parser.parse_args(raw)
    if args.command is None:
        parser.print_help()
        raise SystemExit(2)
    if args.command == "scan" and not args.path and not getattr(args, "sample", None):
        scan.error("give a file path, -, or --sample")
    return args


def _read_input(args: argparse.Namespace) -> str | bytes:
    if getattr(args, "sample", None):
        path = SAMPLE_DIR / SAMPLES[args.sample]
        if not path.exists():
            raise FileNotFoundError(f"Sample is missing: {path}")
        return path.read_bytes()
    if args.path == "-":
        return sys.stdin.read()
    return Path(args.path).read_bytes()


def _print_human(verdict: Verdict, color: bool) -> None:
    label = "Phishing" if verdict.label == "phishing" else "Legitimate"
    percent = round(verdict.phishing_probability * 100)
    painted = _paint(label, "31" if verdict.label == "phishing" else "32", color)
    print(f"{painted}  ·  {percent}% phishing probability")
    if verdict.low_confidence:
        print("Close call. Read the reasons before you trust this.")
    print()
    print(f"Subject: {verdict.subject or '(none)'}")
    print(f"From: {verdict.sender or '(no From header; treated as pasted text)'}")
    print(f"Language model: {round(verdict.text_probability * 100)}% phishing")
    if verdict.clues:
        print("Words that pushed toward phishing: " + ", ".join(verdict.clues))
    print()
    print(textwrap.fill(verdict.summary, width=88))
    reasons = [item for item in verdict.indicators if item.weight > 0]
    reassurances = [item for item in verdict.indicators if item.weight < 0]
    if reasons:
        print("\nReasons")
        for item in reasons:
            print(f"  • {item.title}")
            print(textwrap.fill(item.detail, width=84, initial_indent="    ", subsequent_indent="    "))
    if reassurances:
        print("\nReassuring signals")
        for item in reassurances:
            print(f"  • {item.title}")
            print(textwrap.fill(item.detail, width=84, initial_indent="    ", subsequent_indent="    "))
    if not reasons and not reassurances:
        print("\nNo sender or link signals stood out.")


def _print_headers(headers: dict) -> None:
    if not headers.get("is_raw_email"):
        print("\nNo mail headers in this paste.")
        return
    print(
        f"\nSPF {headers.get('spf', 'none')}  ·  "
        f"DKIM {headers.get('dkim', 'none')}  ·  "
        f"DMARC {headers.get('dmarc', 'none')}"
    )
    for note in headers.get("notes") or []:
        print(f"  • {note['title']}")


def _print_resources(resources: list[dict]) -> None:
    print("\nDomain age and reputation")
    if not resources:
        print("  No public domain to look up.")
        return
    for item in resources:
        roles = ", ".join(item.get("roles") or [])
        label = item.get("domain") or "(unknown)"
        print(f"  {label}" + (f"  ({roles})" if roles else ""))
        if item.get("age_detail"):
            print(f"    {item['age_detail']}")
        if item.get("vt_detail"):
            print(f"    {item['vt_detail']}")
        if item.get("urlscan_detail"):
            print(f"    {item['urlscan_detail']}")
        for url in item.get("urls") or []:
            print(f"    {url}")


def _verdict_from_report(report: dict) -> Verdict:
    indicators = [
        Indicator(item["code"], item["weight"], item["title"], item["detail"])
        for item in [*report.get("reasons", []), *report.get("reassurances", [])]
    ]
    indicators.sort(key=lambda item: item.weight, reverse=True)
    return Verdict(
        label=report["label"],
        phishing_probability=report["phishing_probability"],
        text_probability=report["text_probability"],
        low_confidence=report["low_confidence"],
        summary=report["summary"],
        indicators=indicators,
        clues=list(report.get("clues") or []),
        subject=report.get("subject") or "",
        sender=report.get("sender") or "",
    )


def _paint(text: str, code: str, enabled: bool) -> str:
    if not enabled or sys.environ.get("NO_COLOR"):
        return text
    return f"\033[{code}m{text}\033[0m"
