import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "shorturl.at",
    "ow.ly",
    "buff.ly",
    "rb.gy",
}


SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "password",
    "credential",
    "update",
    "suspended",
    "confirm",
    "wallet",
    "payment",
}


def normalize_url(url: str) -> str:
    url = url.strip()

    if not url:
        raise ValueError("Please enter a URL.")

    if any(ord(character) < 32 for character in url):
        raise ValueError("The URL contains invalid control characters.")

    if any(character.isspace() for character in url):
        raise ValueError("The URL must not contain whitespace.")

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise ValueError("The URL has an invalid format.") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not hostname:
        raise ValueError("The URL must contain a hostname.")

    if "%" in hostname or "\\" in hostname:
        raise ValueError("The hostname contains invalid characters.")

    try:
        hostname.encode("idna")
    except UnicodeError as exc:
        raise ValueError("The hostname is invalid.") from exc

    return urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc,
            parsed.path,
            parsed.query,
            parsed.fragment,
        )
    )


def analyze_url(url: str) -> dict:
    normalized_url = normalize_url(url)
    parsed = urlsplit(normalized_url)

    hostname = parsed.hostname.lower().rstrip(".")

    try:
        hostname_ip = ipaddress.ip_address(hostname)
        is_ip_address = True
    except ValueError:
        hostname_ip = None
        is_ip_address = False

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_hostname = hostname

    signals = []
    risk_score = 0

    def add_signal(name: str, explanation: str, points: int) -> None:
        nonlocal risk_score

        signals.append(
            {
                "name": name,
                "explanation": explanation,
                "points": points,
            }
        )

        risk_score += points

    if is_ip_address:
        add_signal(
            "IP address hostname",
            "The URL uses an IP address instead of a domain name.",
            30,
        )

    if parsed.username is not None or parsed.password is not None:
        add_signal(
            "URL contains user information",
            "The URL contains credentials before the hostname. "
            "This can be used to disguise the actual destination.",
            25,
        )

    if "xn--" in ascii_hostname:
        add_signal(
            "Punycode hostname",
            "The hostname contains an encoded internationalized "
            "domain label that deserves closer inspection.",
            20,
        )

    hostname_without_port = ascii_hostname

    if not is_ip_address and hostname_without_port in SHORTENER_DOMAINS:
        add_signal(
            "URL shortener",
            "The domain belongs to a known URL-shortening service. "
            "The final destination is not visible from this URL alone.",
            15,
        )

    hostname_labels = hostname.split(".")

    if not is_ip_address and len(hostname_labels) >= 5:
        add_signal(
            "Many subdomains",
            "The hostname contains several domain labels, "
            "which can make the destination harder to read.",
            15,
        )

    searchable_text = (
        parsed.path + " " + parsed.query
    ).lower()

    matched_keywords = sorted(
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if re.search(
            rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])",
            searchable_text,
        )
    )

    if matched_keywords:
        add_signal(
            "Sensitive-action keywords",
            "The URL contains words associated with account access "
            "or sensitive actions: "
            + ", ".join(matched_keywords)
            + ".",
            12,
        )

    if len(normalized_url) > 120:
        add_signal(
            "Unusually long URL",
            "The URL is longer than 120 characters, "
            "which can make it harder to inspect.",
            8,
        )

    if parsed.scheme.lower() == "http":
        add_signal(
            "Unencrypted HTTP",
            "The URL uses HTTP instead of HTTPS. "
            "The connection does not provide HTTPS transport protection.",
            5,
        )

    risk_score = min(risk_score, 100)

    if risk_score >= 60:
        risk_level = "high"
        recommendation = (
            "Do not enter passwords, payment details, or other "
            "sensitive information until the destination has been "
            "independently verified."
        )
    elif risk_score >= 30:
        risk_level = "medium"
        recommendation = (
            "Inspect the domain carefully and verify the destination "
            "through an official website or trusted channel."
        )
    else:
        risk_level = "low"
        recommendation = (
            "No strong warning pattern was detected by these initial "
            "rules. This does not guarantee that the URL is safe."
        )

    return {
        "input_url": url,
        "normalized_url": normalized_url,
        "hostname": hostname,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "signals": signals,
        "recommendation": recommendation,
        "disclaimer": (
            "This score is based on heuristic URL patterns, not proof "
            "of malicious activity. A low score does not guarantee safety."
        ),
    }