from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

BASE_DIR = Path(__file__).resolve().parent

DATA_PATH = BASE_DIR / "data" / "messages.csv"
MODEL_DIR = BASE_DIR / "models"
MODEL_PATH = MODEL_DIR / "message_classifier.joblib"

def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATA_PATH}"
        )

    data = pd.read_csv(DATA_PATH)

    required_columns = {"text", "label"}

    if not required_columns.issubset(data.columns):
        raise ValueError(
            "Dataset must contain text and label columns."
        )

    data = data.dropna(subset=["text", "label"]).copy()

    data["text"] = data["text"].astype(str).str.strip()
    data["label"] = (
        data["label"].astype(str).str.strip().str.lower()
    )

    data = data[data["text"] != ""]

    allowed_labels = {"phishing", "legitimate"}

    if not set(data["label"]).issubset(allowed_labels):
        raise ValueError(
            "Labels must be phishing or legitimate."
        )

    data = data.drop_duplicates(subset=["text"])

    print("\nDataset size:", len(data))
    print("\nClass distribution:")
    print(data["label"].value_counts())

    if data["label"].nunique() != 2:
        raise ValueError(
            "The dataset must contain both classes."
        )

    X_train, X_test, y_train, y_test = train_test_split(
        data["text"],
        data["label"],
        test_size=0.25,
        random_state=42,
        stratify=data["label"],
    )

    model = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    strip_accents="unicode",
                    ngram_range=(1, 2),
                    min_df=1,
                    max_features=10000,
                    sublinear_tf=True,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=2000,
                    class_weight="balanced",
                    random_state=42,
                ),
            ),
        ]
    )

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("\nClassification report:")
    print(
        classification_report(
            y_test,
            predictions,
            labels=["legitimate", "phishing"],
            zero_division=0,
        )
    )

    print("\nConfusion matrix:")
    print(
        confusion_matrix(
            y_test,
            predictions,
            labels=["legitimate", "phishing"],
        )
    )

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(
        {
            "model": model,
            "labels": ["legitimate", "phishing"],
            "dataset_size": len(data),
            "training_examples": len(X_train),
            "test_examples": len(X_test),
        },
        MODEL_PATH,
    )

    print(f"\nModel saved to: {MODEL_PATH}")

if __name__ == "__main__":
    main()