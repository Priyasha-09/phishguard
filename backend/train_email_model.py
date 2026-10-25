
from pathlib import Path
import json

import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.pipeline import Pipeline


BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "models"

TRAIN_PATH = DATA_DIR / "email_train.csv"
TEST_PATH = DATA_DIR / "email_test.csv"

MODEL_PATH = MODEL_DIR / "email_classifier.joblib"
METRICS_PATH = MODEL_DIR / "email_model_metrics.json"


def load_data(path):
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

    dataframe = pd.read_csv(path)

    required_columns = {"text", "label"}

    if not required_columns.issubset(dataframe.columns):
        raise ValueError(
            f"{path.name} must contain {required_columns}"
        )

    dataframe = dataframe.dropna(subset=["text", "label"])
    dataframe["text"] = dataframe["text"].astype(str).str.strip()
    dataframe = dataframe[dataframe["text"] != ""]
    dataframe["label"] = dataframe["label"].astype(int)

    if not set(dataframe["label"].unique()).issubset({0, 1}):
        raise ValueError("Labels must be 0 (legitimate) or 1 (phishing/spam).")

    return dataframe


def main():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading training data...")
    train_data = load_data(TRAIN_PATH)

    print("Loading held-out test data...")
    test_data = load_data(TEST_PATH)

    X_train = train_data["text"]
    y_train = train_data["label"]

    X_test = test_data["text"]
    y_test = test_data["label"]

    print("\nTraining examples:", len(train_data))
    print("Test examples:", len(test_data))

    print("\nTraining TF-IDF + Logistic Regression...")

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                strip_accents="unicode",
                ngram_range=(1, 2),
                max_features=50000,
                min_df=2,
                sublinear_tf=True,
                max_df=0.98,
            ),
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=42,
            ),
        ),
    ])

    model.fit(X_train, y_train)

    print("\nEvaluating on held-out test data...")
    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(
        y_test, predictions, pos_label=1, zero_division=0
    )
    recall = recall_score(
        y_test, predictions, pos_label=1, zero_division=0
    )
    f1 = f1_score(
        y_test, predictions, pos_label=1, zero_division=0
    )

    matrix = confusion_matrix(y_test, predictions, labels=[0, 1])

    tn, fp, fn, tp = matrix.ravel()
    false_positive_rate = fp / (fp + tn) if (fp + tn) else 0.0

    print("\nCLASSIFICATION REPORT")
    print(
        classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["legitimate", "phishing_or_spam"],
            zero_division=0,
        )
    )

    print("CONFUSION MATRIX (rows=actual, columns=predicted)")
    print(matrix)
    print("\nSUMMARY METRICS")
    print(f"Accuracy:           {accuracy:.4f}")
    print(f"Phishing precision: {precision:.4f}")
    print(f"Phishing recall:    {recall:.4f}")
    print(f"Phishing F1-score:  {f1:.4f}")
    print(f"False positive rate:{false_positive_rate:.4f}")

    bundle = {
        "model": model,
        "labels": {
            0: "legitimate",
            1: "phishing_or_spam",
        },
        "dataset_size": len(train_data) + len(test_data),
        "training_examples": len(train_data),
        "test_examples": len(test_data),
        "feature_type": "TF-IDF word unigrams and bigrams",
        "algorithm": "Logistic Regression",
        "metrics": {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "false_positive_rate": float(false_positive_rate),
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
        },
        "warning": (
            "Dataset labels include spam as well as phishing. "
            "Evaluation is not proof of real-world phishing performance."
        ),
    }

    joblib.dump(bundle, MODEL_PATH)

    with open(METRICS_PATH, "w", encoding="utf-8") as file:
        json.dump(
            {key: value for key, value in bundle.items() if key != "model"},
            file,
            indent=2,
        )

    print("\nModel saved to:", MODEL_PATH)
    print("Metrics saved to:", METRICS_PATH)
    print("\nTraining and evaluation complete.")


if __name__ == "__main__":
    main()
