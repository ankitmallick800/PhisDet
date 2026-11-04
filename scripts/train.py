"""Train the text classifier and save it into the package.

The public corpus is not shipped. Download it once; this script reads
data/raw/Phishing_Email.csv and writes src/phishdet/artifacts/text_model.joblib.
"""

from __future__ import annotations

import csv
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishdet.model import ARTIFACT_PATH  # noqa: E402
from phishdet.textutil import normalize_text  # noqa: E402

DATA_PATH = ROOT / "data" / "raw" / "Phishing_Email.csv"
DATA_URL = (
    "https://huggingface.co/datasets/zefang-liu/phishing-email-dataset/resolve/main/Phishing_Email.csv"
)
EXPECTED_SHA256 = "18ef4fff1acb8986f0ab01e83ede6025420c829656af5a377560fce17e153b97"
METRICS_PATH = ARTIFACT_PATH.with_name("metrics.json")


def main() -> None:
    if not DATA_PATH.exists():
        _download()
    digest = _sha256(DATA_PATH)
    if digest == EXPECTED_SHA256:
        print(f"Dataset checksum matches ({DATA_PATH.name}).")
    else:
        print(f"Dataset checksum differs from the pinned file: {digest}")

    texts, labels = _load(DATA_PATH)
    phishing = sum(labels)
    print(f"Training rows: {len(texts)} ({phishing} phishing, {len(texts) - phishing} legitimate)")

    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
        roc_auc_score,
    )
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline

    train_text, test_text, train_y, test_y = train_test_split(
        texts,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )
    pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    stop_words="english",
                    ngram_range=(1, 2),
                    min_df=3,
                    max_df=0.9,
                    max_features=20000,
                    sublinear_tf=True,
                    strip_accents="unicode",
                    token_pattern=r"(?u)\b[a-zA-Z][a-zA-Z']+\b",
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    C=1.0,
                    class_weight="balanced",
                    solver="liblinear",
                    max_iter=1000,
                    random_state=42,
                ),
            ),
        ]
    )
    pipeline.fit(train_text, train_y)
    predicted = pipeline.predict(test_text)
    probabilities = pipeline.predict_proba(test_text)[:, list(pipeline.named_steps["clf"].classes_).index(1)]
    precision, recall, f1, _ = precision_recall_fscore_support(
        test_y, predicted, average="binary", pos_label=1
    )
    matrix = confusion_matrix(test_y, predicted, labels=[0, 1]).tolist()
    metrics = {
        "rows": len(texts),
        "phishing": phishing,
        "legitimate": len(texts) - phishing,
        "test_size": len(test_y),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "roc_auc": round(float(roc_auc_score(test_y, probabilities)), 4),
        "accuracy": round(float(accuracy_score(test_y, predicted)), 4),
        "confusion": matrix,
        "dataset": "zefang-liu/phishing-email-dataset",
        "dataset_sha256": digest,
    }
    print(
        "Held-out phishing precision {precision:.3f}  recall {recall:.3f}  "
        "F1 {f1:.3f}  ROC-AUC {roc_auc:.3f}".format(**metrics)
    )
    print(f"Confusion [tn, fp] / [fn, tp]: {matrix}")

    import joblib

    ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    bundle = {"pipeline": pipeline, "metrics": metrics, "version": 1}
    joblib.dump(bundle, ARTIFACT_PATH, compress=3)
    METRICS_PATH.write_text(_json(metrics), encoding="utf-8")
    print(f"Saved {ARTIFACT_PATH} ({ARTIFACT_PATH.stat().st_size} bytes)")
    _score_samples()


def _load(path: Path) -> tuple[list[str], list[int]]:
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
    texts: list[str] = []
    labels: list[int] = []
    seen: set[str] = set()
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        text_key = _field(fields, ("email text", "text", "body"))
        label_key = _field(fields, ("email type", "type", "label"))
        for row in reader:
            label = _label(row.get(label_key) or "")
            raw = row.get(text_key) or ""
            if label is None or not raw.strip():
                continue
            if len(raw) > 50000:
                raw = raw[:50000]
            text = normalize_text(raw)
            if len(text) < 20:
                continue
            key = text[:400]
            if key in seen:
                continue
            seen.add(key)
            texts.append(text)
            labels.append(label)
    if not texts or len(set(labels)) < 2:
        raise SystemExit(f"No usable labeled rows in {path}")
    return texts, labels


def _field(fields: list[str], names: tuple[str, ...]) -> str:
    for field in fields:
        if field and field.strip().lower() in names:
            return field
    for field in fields:
        if not field:
            continue
        lowered = field.strip().lower()
        if any(name in lowered for name in names):
            return field
    raise SystemExit(f"Could not find a column matching {names} in {fields}")


def _label(value: str) -> int | None:
    text = value.strip().lower()
    if not text:
        return None
    if "phish" in text or text in {"1", "spam", "scam"}:
        return 1
    if "safe" in text or "legit" in text or "ham" in text or text == "0":
        return 0
    return None


def _download() -> None:
    import urllib.request

    DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {DATA_URL}")
    urllib.request.urlretrieve(DATA_URL, DATA_PATH)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json(metrics: dict) -> str:
    import json

    return json.dumps(metrics, indent=2) + "\n"


def _score_samples() -> None:
    from phishdet.detect import detect

    sample_dir = ROOT / "src" / "phishdet" / "samples"
    print("Built-in samples:")
    for path in sorted(sample_dir.glob("*.eml")):
        verdict = detect(path.read_text(encoding="utf-8"))
        print(
            f"  {path.name:16} {verdict.label:11} "
            f"p={verdict.phishing_probability:.3f} text={verdict.text_probability:.3f}"
        )


if __name__ == "__main__":
    main()
