"""Load the trained text model and score wording."""

from __future__ import annotations

from pathlib import Path

from phishdet.textutil import normalize_text

ARTIFACT_PATH = Path(__file__).resolve().parent / "artifacts" / "text_model.joblib"
_BUNDLE: dict | None = None


def load_bundle() -> dict:
    global _BUNDLE
    if _BUNDLE is not None:
        return _BUNDLE
    if not ARTIFACT_PATH.exists():
        raise FileNotFoundError(
            f"No trained model at {ARTIFACT_PATH}. From the repo root, run: python scripts/train.py"
        )
    import joblib

    bundle = joblib.load(ARTIFACT_PATH)
    if "pipeline" not in bundle:
        raise FileNotFoundError(f"Model file is missing a pipeline: {ARTIFACT_PATH}")
    _BUNDLE = bundle
    return bundle


def score_text(text: str) -> tuple[float, list[str]]:
    """Return the phishing probability of the wording, and the tokens behind it."""
    normalized = normalize_text(text)
    if len(normalized) < 12:
        return 0.5, []
    bundle = load_bundle()
    pipeline = bundle["pipeline"]
    classifier = pipeline.named_steps["clf"]
    classes = [int(label) for label in classifier.classes_]
    probabilities = pipeline.predict_proba([normalized])[0]
    phishing = float(probabilities[classes.index(1)])
    return phishing, _token_clues(pipeline, normalized)


def _token_clues(pipeline, normalized: str, limit: int = 5) -> list[str]:
    vectorizer = pipeline.named_steps["tfidf"]
    classifier = pipeline.named_steps["clf"]
    matrix = vectorizer.transform([normalized]).tocoo()
    if matrix.nnz == 0:
        return []
    coefficients = classifier.coef_.ravel()
    names = vectorizer.get_feature_names_out()
    ranked = sorted(
        (
            (float(coefficients[index] * value), str(names[index]))
            for index, value in zip(matrix.col, matrix.data)
        ),
        reverse=True,
    )
    clues = [token for score, token in ranked if score > 0 and token != "url"]
    return clues[:limit]
