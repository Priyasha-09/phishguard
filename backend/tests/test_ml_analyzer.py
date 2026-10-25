
from app.ml_analyzer import analyze_message_ml


def test_empty_message_is_rejected():
    try:
        analyze_message_ml("")
    except ValueError:
        return

    raise AssertionError("Empty messages should be rejected.")


def test_whitespace_message_is_rejected():
    try:
        analyze_message_ml("   ")
    except ValueError:
        return

    raise AssertionError("Whitespace-only messages should be rejected.")


def test_oversized_message_is_rejected():
    try:
        analyze_message_ml("A" * 10001)
    except ValueError:
        return

    raise AssertionError("Oversized messages should be rejected.")


def test_suspicious_message_returns_valid_result():
    result = analyze_message_ml(
        "URGENT! Your account will be suspended. "
        "Verify your password immediately."
    )

    assert result["prediction"] in {
        "legitimate",
        "phishing_or_spam",
    }

    assert 0 <= result["risk_score"] <= 100

    assert result["risk_level"] in {
        "low",
        "medium",
        "high",
    }

    assert result["model"] == "TF-IDF + Logistic Regression"

    assert result["model_evaluation"]["test_examples"] == 5000

    assert isinstance(result["signals"], list)

    assert result["recommendation"]


def test_legitimate_message_returns_valid_result():
    result = analyze_message_ml(
        "Hi team, our project meeting is scheduled "
        "for tomorrow at 10 AM. Please bring your updates."
    )

    assert result["prediction"] in {
        "legitimate",
        "phishing_or_spam",
    }

    assert 0 <= result["risk_score"] <= 100

    assert result["risk_level"] in {
        "low",
        "medium",
        "high",
    }

    assert result["recommendation"]


def test_disclaimer_explains_model_limitations():
    result = analyze_message_ml(
        "Your delivery will arrive tomorrow."
    )

    assert "not a calibrated probability" in result["disclaimer"]
