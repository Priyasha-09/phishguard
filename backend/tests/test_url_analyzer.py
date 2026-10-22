
import pytest

from app.url_analyzer import analyze_url, normalize_url


def test_ip_address_url_is_flagged():
    result = analyze_url("http://192.0.2.1/login")

    assert result["risk_score"] == 47
    assert result["risk_level"] == "medium"
    assert len(result["signals"]) == 3


def test_ordinary_url_has_no_warning_signals():
    result = analyze_url("https://www.wikipedia.org/")

    assert result["risk_score"] == 0
    assert result["risk_level"] == "low"
    assert result["signals"] == []


def test_url_without_scheme_is_normalized():
    result = analyze_url("www.wikipedia.org")

    assert result["normalized_url"] == "https://www.wikipedia.org"


def test_empty_url_is_rejected():
    with pytest.raises(ValueError, match="Please enter a URL"):
        analyze_url("")


def test_unsupported_scheme_is_rejected():
    with pytest.raises(ValueError, match="Only HTTP and HTTPS"):
        analyze_url("ftp://example.com/file")


def test_url_with_credentials_is_flagged():
    result = analyze_url("https://user:password@example.com/login")

    signal_names = [signal["name"] for signal in result["signals"]]

    assert "URL contains user information" in signal_names


def test_whitespace_in_url_is_rejected():
    with pytest.raises(ValueError, match="whitespace"):
        normalize_url("https://example.com/some page")


def test_url_with_sensitive_keyword_is_flagged():
    result = analyze_url("https://example.com/account")

    signal_names = [signal["name"] for signal in result["signals"]]

    assert "Sensitive-action keywords" in signal_names


def test_result_contains_safety_disclaimer():
    result = analyze_url("https://www.wikipedia.org/")

    assert "disclaimer" in result
    assert "does not guarantee safety" in result["disclaimer"]

