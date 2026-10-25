
from pathlib import Path

import joblib


MODEL_PATH = (
    Path(__file__).resolve().parents[1]
    / "models"
    / "email_classifier.joblib"
)

_model_bundle = None


def load_model():
    global _model_bundle

    if _model_bundle is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Trained email model not found: {MODEL_PATH}"
            )

        _model_bundle = joblib.load(MODEL_PATH)

    return _model_bundle


def analyze_message_ml(message: str) -> dict:
    if not isinstance(message, str) or not message.strip():
        raise ValueError("Message cannot be empty.")

    if len(message) > 10000:
        raise ValueError("Message cannot exceed 10,000 characters.")

    bundle = load_model()
    model = bundle["model"]

    probabilities = model.predict_proba([message])[0]
    classes = list(model.classes_)

    phishing_index = classes.index(1)
    phishing_score = float(probabilities[phishing_index])

    prediction = int(model.predict([message])[0])

    risk_score = round(phishing_score * 100)

    if risk_score >= 70:
        risk_level = "high"
    elif risk_score >= 40:
        risk_level = "medium"
    else:
        risk_level = "low"

    signals = []

    text_lower = message.lower()

    if any(
        phrase in text_lower
        for phrase in [
            "verify your account",
            "confirm your password",
            "login immediately",
            "account suspended",
        ]
    ):
        signals.append("Potential account verification or threat language")

    if any(
        phrase in text_lower
        for phrase in [
            "urgent",
            "immediately",
            "within 24 hours",
            "act now",
        ]
    ):
        signals.append("Urgency or pressure language")

    if any(
        phrase in text_lower
        for phrase in [
            "password",
            "credit card",
            "bank details",
            "one-time password",
            "otp",
        ]
    ):
        signals.append("Request or reference to sensitive information")

    if not signals:
        signals.append(
            "The text classifier evaluated the message for learned patterns"
        )

    if prediction == 1:
        recommendation = (
            "Treat this message cautiously. Do not click suspicious links "
            "or share credentials. Verify the sender through an official "
            "website or trusted contact method."
        )
    else:
        recommendation = (
            "The model did not classify this message as phishing or spam. "
            "This does not guarantee safety. Verify unexpected requests "
            "through an independent, trusted channel."
        )

    return {
        "prediction": (
            "phishing_or_spam" if prediction == 1 else "legitimate"
        ),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "signals": signals,
        "recommendation": recommendation,
        "model": "TF-IDF + Logistic Regression",
        "model_version": "email-classifier-v1",
        "model_evaluation": {
            "test_examples": bundle["test_examples"],
            "test_accuracy": round(
                bundle["metrics"]["accuracy"] * 100, 2
            ),
            "test_f1_score": round(
                bundle["metrics"]["f1_score"] * 100, 2
            ),
        },
        "disclaimer": (
            "The score is the model's estimated phishing/spam score, "
            "not a calibrated probability. The training dataset includes "
            "spam as well as phishing. No automated result guarantees "
            "that a message is safe or malicious."
        ),
    }
