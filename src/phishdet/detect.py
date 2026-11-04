"""Combine the text model with sender and link signals."""

from __future__ import annotations

import math
from dataclasses import dataclass

from phishdet.model import score_text
from phishdet.parse import ParsedEmail, parse_email
from phishdet.signals import Indicator, extract_signals

_MAX_CHARS = 2_000_000
_HIGH_RISK = 1.5
# A sender or link signal is enough to trust the usual 50% line.
# Wording alone has to be more sure: short ordinary notes often land near 50%.
_SIGNAL_THRESHOLD = 0.5
_TEXT_ONLY_THRESHOLD = 0.70


@dataclass
class Verdict:
    label: str
    phishing_probability: float
    text_probability: float
    low_confidence: bool
    summary: str
    indicators: list[Indicator]
    clues: list[str]
    subject: str
    sender: str

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "phishing_probability": round(self.phishing_probability, 4),
            "text_probability": round(self.text_probability, 4),
            "low_confidence": self.low_confidence,
            "summary": self.summary,
            "reasons": [item.to_dict() for item in self.indicators if item.weight > 0],
            "reassurances": [item.to_dict() for item in self.indicators if item.weight < 0],
            "clues": self.clues,
            "subject": self.subject,
            "sender": self.sender,
        }


def detect(raw: str | bytes) -> Verdict:
    if isinstance(raw, bytes):
        if not raw.strip():
            raise ValueError("Paste an email first.")
        if len(raw) > _MAX_CHARS:
            raise ValueError("Email is larger than 2 MB.")
    else:
        if not raw or not raw.strip():
            raise ValueError("Paste an email first.")
        if len(raw) > _MAX_CHARS:
            raise ValueError("Email is larger than 2 MB.")

    parsed = parse_email(raw)
    return score_parsed(parsed)


def score_parsed(parsed: ParsedEmail) -> Verdict:
    source = "\n".join(part for part in (parsed.subject, parsed.body_text) if part)
    text_probability, clues = score_text(source)
    # Weak token hits on ordinary mail ("check", a person's name) are noise.
    if text_probability < 0.5:
        clues = []
    indicators = extract_signals(parsed)
    probability = _combine(text_probability, indicators)
    threshold = _threshold(indicators)
    label = "phishing" if probability >= threshold else "legitimate"
    sender = parsed.from_header.strip()
    return Verdict(
        label=label,
        phishing_probability=probability,
        text_probability=text_probability,
        low_confidence=abs(probability - threshold) <= 0.10,
        summary=_summarize(label, indicators),
        indicators=indicators,
        clues=clues,
        subject=parsed.subject.strip(),
        sender=sender,
    )


def with_extra(verdict: Verdict, extra: list[Indicator]) -> Verdict:
    """Re-score a verdict after reputation checks add indicators."""
    indicators = [*verdict.indicators, *extra]
    indicators.sort(key=lambda item: item.weight, reverse=True)
    probability = _combine(verdict.text_probability, indicators)
    threshold = _threshold(indicators)
    label = "phishing" if probability >= threshold else "legitimate"
    return Verdict(
        label=label,
        phishing_probability=probability,
        text_probability=verdict.text_probability,
        low_confidence=abs(probability - threshold) <= 0.10,
        summary=_summarize(label, indicators),
        indicators=indicators,
        clues=list(verdict.clues),
        subject=verdict.subject,
        sender=verdict.sender,
    )


def _threshold(indicators: list[Indicator]) -> float:
    if any(item.weight > 0 for item in indicators):
        return _SIGNAL_THRESHOLD
    return _TEXT_ONLY_THRESHOLD


def _combine(text_probability: float, indicators: list[Indicator]) -> float:
    weight = sum(item.weight for item in indicators)
    weight = max(-2.5, min(4.5, weight))
    probability = _logistic(_logit(text_probability) + weight)
    known_sender = any(item.code == "links_match_known_sender" for item in indicators)
    high_risk = any(item.weight >= _HIGH_RISK for item in indicators)
    # A real password reset from the company's own domain uses the same
    # words as a phish. Matching links on a known domain pull that back,
    # unless something sharper (a password field, a lookalike host) is present.
    if known_sender and not high_risk:
        probability = min(probability, 0.42)
    return probability


def _summarize(label: str, indicators: list[Indicator]) -> str:
    risks = [item for item in indicators if item.weight > 0]
    reassurances = [item for item in indicators if item.weight < 0]
    if label == "phishing":
        if risks:
            lead = risks[0]
            return f"{lead.title}. {lead.detail}"
        return (
            "The wording matches phishing and scam mail from the training set. "
            "No spoofed sender or deceptive link stood out."
        )
    if reassurances:
        return reassurances[0].detail
    return "The wording, links, and sender did not clear the phishing threshold."


def _logit(probability: float) -> float:
    bounded = min(max(probability, 1e-6), 1 - 1e-6)
    return math.log(bounded / (1 - bounded))


def _logistic(value: float) -> float:
    if value >= 20:
        return 1.0
    if value <= -20:
        return 0.0
    return 1.0 / (1.0 + math.exp(-value))
