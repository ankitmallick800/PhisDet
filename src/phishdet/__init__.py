"""Read an email and estimate whether it is phishing."""

__version__ = "0.1.0"

__all__ = ["__version__", "detect"]


def detect(raw: str | bytes):
    """Score one email. Imported lazily so signal tests stay light."""
    from phishdet.detect import detect as _detect

    return _detect(raw)
