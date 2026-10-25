import re


URGENCY_PHRASES = {
    "act immediately": 15,
    "immediately": 10,
    "urgent": 10,
    "within 24 hours": 15,
    "account will be suspended": 20,
    "account has been suspended": 20,
    "expires today": 15,
    "final warning": 15,
    "act now": 12,
}

CREDENTIAL_PHRASES = {
    "verify your password": 25,
    "confirm your password": 25,
    "enter your password": 25,
    "verify your account": 15,
    "confirm your account": 15,
    "login credentials": 20,
    "one time password": 15,
    "otp": 10,
    "security code": 10,
}

FINANCIAL_PHRASES = {
"payment failed": 10,
"claim your prize": 20,
"you have won": 15,
"bank account": 5,
"refund pending": 10,
"pay immediately": 20,
"update your payment": 15,
"redelivery fee": 15,
"redelivery charge": 15,
"delivery fee": 10,
"delivery charge": 10,
"pay a fee": 15,
"pay the fee": 15,
"small fee": 10,
"customs fee": 15,
"shipping fee": 10,
"payment required": 15,
"outstanding balance": 10,
}


LINK_PHRASES = {
    "click here": 10,
    "click the link": 10,
    "open this link": 10,
    "tap here": 10,
}


def find_matching_phrases(
    text: str,
    phrase_scores: dict[str, int],
) -> list[dict]:
    matches = []

    for phrase, points in phrase_scores.items():
        pattern = (
            r"(?<![a-z0-9])"
            + re.escape(phrase)
            + r"(?![a-z0-9])"
        )

        if re.search(pattern, text, flags=re.IGNORECASE):
            matches.append(
                {
                    "phrase": phrase,
                    "points": points,
                }
            )

    return matches


def analyze_message(message: str) -> dict:
    if not isinstance(message, str) or not message.strip():
        raise ValueError("Please enter a message to analyze.")

    if len(message) > 10000:
        raise ValueError(
            "The message must contain no more than 10,000 characters."
        )

    urgency_matches = find_matching_phrases(
        message,
        URGENCY_PHRASES,
    )

    credential_matches = find_matching_phrases(
        message,
        CREDENTIAL_PHRASES,
    )

    financial_matches = find_matching_phrases(
        message,
        FINANCIAL_PHRASES,
    )

    link_matches = find_matching_phrases(
        message,
        LINK_PHRASES,
    )

    signals = []

    def add_signal(
        name: str,
        explanation: str,
        matches: list[dict],
    ) -> None:
        if not matches:
            return

        signals.append(
            {
                "name": name,
                "explanation": explanation,
                "matched_phrases": [
                    match["phrase"] for match in matches
                ],
                "points": min(
                    sum(match["points"] for match in matches),
                    30,
                ),
            }
        )

    add_signal(
        "Urgency or pressure",
        "The message uses urgent language that may pressure "
        "the recipient into acting without checking the request.",
        urgency_matches,
    )

    add_signal(
        "Credential or verification request",
        "The message refers to passwords, account verification, "
        "or security codes. Never share sensitive credentials "
        "through an unverified message.",
        credential_matches,
    )

    add_signal(
        "Financial or reward language",
        "The message contains payment, banking, refund, "
        "or prize-related language that deserves context.",
        financial_matches,
    )

    add_signal(
        "Link-clicking instruction",
        "The message encourages the recipient to open a link. "
        "Check the destination independently before visiting it.",
        link_matches,
    )

    risk_score = min(
        sum(signal["points"] for signal in signals),
        100,
    )

    if risk_score >= 60:
        risk_level = "high"
        recommendation = (
            "Treat this message as suspicious. Do not click links "
            "or share passwords, security codes, or payment details. "
            "Verify the request through an official channel."
        )
    elif risk_score >= 30:
        risk_level = "medium"
        recommendation = (
            "Check the sender and verify the request independently "
            "before clicking links, sharing information, or paying."
        )
    else:
        risk_level = "low"
        recommendation = (
            "Few warning patterns were detected by these initial "
            "rules. This does not guarantee that the message is safe."
        )

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "signals": signals,
        "recommendation": recommendation,
        "disclaimer": (
            "This score is based on message wording and simple rules. "
            "It is not proof of malicious activity. A low score does "
            "not guarantee safety."
        ),
    }
