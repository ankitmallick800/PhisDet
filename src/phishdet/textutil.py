"""Text normalization shared by training and scoring."""

from __future__ import annotations

import html
import re

_TAGS = re.compile(r"<[^>]+>")
_URLS = re.compile(r"(?i)\b(?:https?://|hxxps?://|www\.)\S+")
_SPACE = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    """Collapse an email body into the form the text model was trained on.

    URLs are replaced with a single token so the classifier learns wording
    rather than particular domains. Link structure is scored separately.
    """
    text = html.unescape(text or "")
    text = _TAGS.sub(" ", text)
    text = _URLS.sub(" url ", text)
    text = text.replace("\x00", " ")
    text = text.lower()
    text = _SPACE.sub(" ", text).strip()
    return text[:20000]
