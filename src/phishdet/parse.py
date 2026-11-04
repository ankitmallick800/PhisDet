"""Turn a raw message, .eml file, or pasted body into structured fields."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser, Parser
from html.parser import HTMLParser

_HEADER_START = re.compile(
    r"^(?:from|subject|date|to|cc|bcc|received|mime-version|return-path|"
    r"reply-to|delivered-to|message-id|content-type)\s*:",
    re.IGNORECASE,
)


@dataclass
class Link:
    href: str
    text: str


@dataclass
class Attachment:
    filename: str
    content_type: str


@dataclass
class ParsedEmail:
    subject: str
    from_header: str
    reply_to: str
    return_path: str
    to_header: str
    text: str
    html: str
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    has_password_field: bool = False
    has_form: bool = False
    is_raw_email: bool = False
    message_id: str = ""
    date: str = ""
    authentication_results: str = ""
    received_spf: str = ""
    has_dkim_signature: bool = False

    @property
    def body_text(self) -> str:
        return self.text.strip()


class _HTMLExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[Link] = []
        self.has_password_field = False
        self.has_form = False
        self._skip = 0
        self._href: str | None = None
        self._link_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if self._skip:
            if tag in {"script", "style"}:
                self._skip += 1
            return
        if tag in {"script", "style"}:
            self._skip += 1
            return
        attr = {key.lower(): (value or "") for key, value in attrs}
        if tag == "form":
            self.has_form = True
        if tag == "input":
            field_type = attr.get("type", "").lower()
            field_name = attr.get("name", "").lower()
            if field_type == "password" or "pass" in field_name:
                self.has_password_field = True
        if tag == "a":
            self._href = attr.get("href", "").strip()
            self._link_parts = []
        if tag == "br":
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in {"script", "style"} and self._skip:
            self._skip -= 1
            return
        if self._skip:
            return
        if tag == "a" and self._href is not None:
            self.links.append(Link(self._href, "".join(self._link_parts).strip()))
            self._href = None
            self._link_parts = []
        if tag in {"p", "div", "tr", "li", "h1", "h2", "h3", "table"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        self.parts.append(data)
        if self._href is not None:
            self._link_parts.append(data)


def extract_html(html: str) -> tuple[str, list[Link], bool, bool]:
    parser = _HTMLExtractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass
    text = re.sub(r"[ \t]+\n", "\n", "".join(parser.parts))
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text, parser.links, parser.has_password_field, parser.has_form


def looks_like_raw_email(text: str) -> bool:
    head = text.lstrip("\ufeff").lstrip()
    if head.startswith("From "):
        rest = head.split("\n", 1)[1] if "\n" in head else ""
        first_rest = rest.lstrip().splitlines()[0].strip() if rest.strip() else ""
        if not _HEADER_START.match(first_rest):
            return False
        head = rest.lstrip()
    first = head.splitlines()[0].strip() if head else ""
    return bool(_HEADER_START.match(first))


def _decode_part(part: EmailMessage) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    if not isinstance(payload, bytes):
        return str(payload)
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _from_loose_text(text: str) -> ParsedEmail:
    stripped = text.strip()
    looks_html = bool(re.search(r"(?i)<\s*(html|body|a|p|div|table|form)\b", stripped))
    if looks_html:
        visible, links, password, form = extract_html(stripped)
        return ParsedEmail(
            subject="",
            from_header="",
            reply_to="",
            return_path="",
            to_header="",
            text=visible or stripped,
            html=stripped,
            links=links,
            has_password_field=password,
            has_form=form,
            is_raw_email=False,
        )
    return ParsedEmail(
        subject="",
        from_header="",
        reply_to="",
        return_path="",
        to_header="",
        text=stripped,
        html="",
        is_raw_email=False,
    )


def _from_message(message: EmailMessage) -> ParsedEmail:
    plain_parts: list[str] = []
    html_visible: list[str] = []
    html_raw: list[str] = []
    links: list[Link] = []
    attachments: list[Attachment] = []
    password = False
    form = False

    parts = list(message.walk()) if message.is_multipart() else [message]
    for part in parts:
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename() or ""
        if disposition == "attachment" or (
            filename and content_type not in {"text/plain", "text/html"}
        ):
            attachments.append(Attachment(filename=filename, content_type=content_type))
            continue
        if content_type == "text/plain":
            plain_parts.append(_decode_part(part))
        elif content_type == "text/html":
            html = _decode_part(part)
            html_raw.append(html)
            visible, part_links, part_password, part_form = extract_html(html)
            html_visible.append(visible)
            links.extend(part_links)
            password = password or part_password
            form = form or part_form
        elif filename:
            attachments.append(Attachment(filename=filename, content_type=content_type))

    plain = "\n".join(part.strip() for part in plain_parts if part and part.strip())
    visible_html = "\n".join(part for part in html_visible if part)
    authentication = _header_values(message, "authentication-results")
    authentication += "\n" + _header_values(message, "arc-authentication-results")
    return ParsedEmail(
        subject=str(message.get("subject") or ""),
        from_header=str(message.get("from") or ""),
        reply_to=str(message.get("reply-to") or ""),
        return_path=str(message.get("return-path") or ""),
        to_header=str(message.get("to") or ""),
        text=plain or visible_html,
        html="\n".join(html_raw),
        links=links,
        attachments=attachments,
        has_password_field=password,
        has_form=form,
        is_raw_email=True,
        message_id=str(message.get("message-id") or ""),
        date=str(message.get("date") or ""),
        authentication_results=authentication.strip(),
        received_spf=_header_values(message, "received-spf"),
        has_dkim_signature=bool(message.get_all("dkim-signature")),
    )


def _header_values(message: EmailMessage, name: str) -> str:
    values = message.get_all(name) or []
    return "\n".join(str(value) for value in values if value)


def parse_email(raw: str | bytes) -> ParsedEmail:
    if isinstance(raw, bytes):
        if raw.startswith(b"\xd0\xcf\x11\xe0"):
            raise ValueError(
                "This looks like an Outlook .msg file. Save it as .eml, or paste the message text."
            )
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1", errors="replace")
        source: str | bytes = raw
    else:
        text = raw.lstrip("\ufeff")
        source = text

    if text.count("\x00") > 10:
        raise ValueError("This file does not look like an email.")
    if not looks_like_raw_email(text):
        return _from_loose_text(text)

    try:
        if isinstance(source, bytes):
            message = BytesParser(policy=policy.default).parsebytes(source)
        else:
            message = Parser(policy=policy.default).parsestr(source)
    except Exception as exc:
        raise ValueError("Could not parse that email.") from exc
    return _from_message(message)
