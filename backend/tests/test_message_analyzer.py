import pytest

from app.message_analyzer import analyze_message


def test_suspicious_message_is_flagged():
    message = (
        "URGENT! Your bank account will be suspended today. "
        "Verify your password immediately. Click here to restore access."
    )

    result = analyze_message(message)

    assert result["risk_score"] >= 60
    assert result["risk_level"] == "high"
    assert len(result["signals"]) == 4


def test_ordinary_message_has_no_warning_signals():
    message = (
        "Hi, are we still meeting at the library tomorrow afternoon?"
    )

    result = analyze_message(message)

    assert result["risk_score"] == 0
    assert result["risk_level"] == "low"
    assert result["signals"] == []


def test_empty_message_is_rejected():
    with pytest.raises(
        ValueError,
        match="Please enter a message",
    ):
        analyze_message("")


def test_whitespace_only_message_is_rejected():
    with pytest.raises(
        ValueError,
        match="Please enter a message",
    ):
        analyze_message("   ")


def test_oversized_message_is_rejected():
    with pytest.raises(
        ValueError,
        match="10,000 characters",
    ):
        analyze_message("a" * 10001)


def test_password_request_is_flagged():
    result = analyze_message(
        "Please verify your password immediately."
    )

    signal_names = [
        signal["name"] for signal in result["signals"]
    ]

    assert "Credential or verification request" in signal_names


def test_urgency_is_flagged():
    result = analyze_message(
        "URGENT! Please act immediately."
    )

    signal_names = [
        signal["name"] for signal in result["signals"]
    ]

    assert "Urgency or pressure" in signal_names


def test_link_instruction_is_flagged():
    result = analyze_message(
        "Click here to view your account."
    )

    signal_names = [
        signal["name"] for signal in result["signals"]
    ]

    assert "Link-clicking instruction" in signal_names


def test_result_contains_disclaimer():
    result = analyze_message("Hello, how are you?")

    assert "disclaimer" in result
    assert "does not guarantee safety" in result["disclaimer"]
