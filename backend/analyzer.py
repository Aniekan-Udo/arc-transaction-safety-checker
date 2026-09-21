"""
analyzer.py

Takes the structured facts produced by scanner.py and turns them into:
    1. A weighted risk score (0-100), mapped to a risk band.
    2. A recommendation derived from that band.
    3. A plain-language explanation of what the transaction does.

Design decisions (see README's "Key Design Decisions" for the full reasoning):
    - Scoring is rule-based, and so is the explanation wherever scanner.py
      managed to decode the transaction. A template is instant, free, and
      cannot hallucinate; for a safety tool those matter more than variety.
    - The LLM is asked for wording in one case only -- a call we could not
      decode, which is the one case rules have nothing to say about.
    - It has no influence on the score whatsoever. Every input to the verdict
      is a rule in WEIGHTS, so swapping providers (or losing one entirely)
      changes how a result reads and nothing else. An earlier version let the
      model escalate an undecodable call; it flagged concern on every one it
      saw, established contracts included, so that judgement is now a plain
      weight -- same outcome, no network call, and testable.
    - Clear-cut cases (a direct known-scam match) never reach a model.
"""

import re

from llm import LLMError, LLMProvider


# ---------------------------------------------------------------------------
# Step 1: Weighted risk scoring (rule-based, deterministic)
# ---------------------------------------------------------------------------

# Tune these weights once you've tested against real examples.
WEIGHTS = {
    "known_scam": 70,          # near-certain: direct blocklist match
    "unlimited_approval": 35,  # strong signal on its own
    "fresh_contract": 25,      # compounds with unlimited_approval
    "undecoded_function": 35,  # MEDIUM on its own: being unable to read what
                               # you are authorising is its own risk, and is
                               # never "safe". Matches unlimited_approval --
                               # both mean "you don't know what you granted".
}

FRESH_CONTRACT_THRESHOLD_HOURS = 24

# Headroom for the answer itself: thinking-capable models spend tokens before
# they emit any text, and a truncated verdict is worse than a slow one.
MAX_EXPLANATION_TOKENS = 1000

# The recommendation is derived from the band, never asked of the model: it
# is the line users act on, so it follows from the deterministic score the
# same way every time, whichever provider wrote the wording.
BAND_RECOMMENDATION = {
    "SAFE": "Safe to proceed",
    "LOW": "Proceed with caution",
    "MEDIUM": "Proceed with caution",
    "HIGH": "Do not sign this transaction",
    "CRITICAL": "Do not sign this transaction",
}


def compute_risk_score(facts: dict) -> int:
    """
    Combine individual heuristic flags into one 0-100 score.
    Diminishing returns aren't implemented here on purpose -- keep the
    first version simple and additive, capped at 100. Refine later if
    real test transactions show it's too aggressive or too lax.
    """
    score = 0

    # Explicitly True only: None means the check couldn't run, not "clean".
    if facts.get("known_scam") is True:
        score += WEIGHTS["known_scam"]

    if facts.get("unlimited_approval"):
        score += WEIGHTS["unlimited_approval"]

    age = facts.get("contract_age_hours")
    if age is not None and age < FRESH_CONTRACT_THRESHOLD_HOURS:
        score += WEIGHTS["fresh_contract"]

    # A plain transfer has no function to decode and nothing unverified about
    # it -- only penalise calldata we actually failed to read.
    if facts.get("function") is None and not facts.get("is_plain_transfer"):
        score += WEIGHTS["undecoded_function"]

    return min(score, 100)


def score_to_band(score: int) -> str:
    """Map a numeric score to a human-facing risk band."""
    if score >= 70:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "SAFE"


# ---------------------------------------------------------------------------
# Step 2a: Deterministic wording for anything we decoded
# ---------------------------------------------------------------------------

KNOWN_SCAM_EXPLANATION = (
    "This address is on a known list of scam or malicious addresses."
)

UNDECODED_EXPLANATION = (
    "What this transaction does could not be determined, so it could not be "
    "checked properly."
)


def _address_clause(facts: dict) -> str:
    """
    What we know about the address on the other side. Says "could not check"
    rather than staying silent, so an unverified address never reads as a
    verified-clean one.
    """
    age = facts.get("contract_age_hours")
    if age is None:
        return " We could not check how long that address has existed."
    if age < 1:
        # "0 hours ago" reads like a rounding error in the one sentence
        # where the alarm matters most.
        return " That address was created less than an hour ago."
    if age < FRESH_CONTRACT_THRESHOLD_HOURS:
        hours = round(age)
        return f" That address was created only {hours} hour{'s' if hours != 1 else ''} ago."
    return ""


def describe(facts: dict) -> str | None:
    """
    Plain-language wording built from verified facts alone.

    Returns None when the transaction is not a pattern we decoded -- that is
    the only case a model gets asked about. Deliberately avoids printing raw
    token amounts: without the token's decimals a 27-digit integer tells a
    non-technical reader nothing, so describe the bound instead.
    """
    counterparty = facts.get("counterparty")

    if facts.get("is_plain_transfer"):
        return (
            f"This sends funds to {counterparty}. It does not give anyone "
            "ongoing permission to spend your money."
        )

    function = facts.get("function")

    if function == "approve":
        if facts.get("unlimited_approval"):
            base = (
                f"This lets {counterparty} spend your tokens at any time, in "
                "any amount, for as long as you leave the permission in place."
            )
        else:
            base = (
                f"This lets {counterparty} spend a limited amount of your "
                "tokens, and no more than that amount."
            )
        return base + _address_clause(facts)

    if function == "transferFrom":
        params = facts.get("params") or {}
        return (
            f"This moves tokens out of {params.get('from')} and sends them to "
            f"{params.get('to')}." + _address_clause(facts)
        )

    return None


# ---------------------------------------------------------------------------
# Step 2b: The LLM, for undecodable calls only
# ---------------------------------------------------------------------------

UNKNOWN_CALL_PROMPT = """A safety tool could not decode what a crypto transaction does. Explain the
situation to a non-technical person.

These facts are already verified. Do not question them, and do not invent
anything they do not state -- you do not know what this transaction does, and
saying so plainly is the correct answer.

Facts:
- Contract being called: {to}
- Function signature (first four bytes): {selector}
- The tool could not decode this function, so its behaviour is unknown
- That address's contract age (hours): {contract_age_hours}
- That address matches a known scam address: {known_scam}

Reply with one plain-English sentence, max 30 words, no preamble: say that
what this does could not be determined, and note anything relevant from the
facts above. Avoid jargon like "ERC-20" or "calldata". Do not guess at funds
moving, and do not give a verdict or advice on whether to sign -- the risk
decision is made from the facts above, not from your wording.
"""


def _unknown_if_none(value, label: str = "could not be verified"):
    return label if value is None else value


def _first_sentence(text: str) -> str:
    """
    Take the model's sentence, tolerating leading numbering or a stray extra
    line -- providers vary in how literally they follow the format.
    """
    for line in text.splitlines():
        line = re.sub(r"^\s*\d+[.)]\s*", "", line).strip()
        if line:
            return line
    return UNDECODED_EXPLANATION


def explain_transaction(provider: LLMProvider | None, facts: dict) -> dict:
    """
    Produce the wording, and say where it came from.

    Returns {"explanation": str, "source": str} where source is "rules"
    (built from verified facts), "model", or "unavailable" (no working
    provider). None of these affect the score.
    """
    if facts.get("known_scam") is True:
        # Clear-cut and serious: a canned line beats any generated phrasing.
        return {"explanation": KNOWN_SCAM_EXPLANATION, "source": "rules"}

    described = describe(facts)
    if described is not None:
        return {"explanation": described, "source": "rules"}

    # Genuinely undecodable -- the one case rules have nothing to add.
    if provider is None:
        return {"explanation": UNDECODED_EXPLANATION, "source": "unavailable"}

    prompt = UNKNOWN_CALL_PROMPT.format(
        to=facts.get("to"),
        selector=facts.get("selector") or "unknown",
        contract_age_hours=_unknown_if_none(facts.get("contract_age_hours")),
        known_scam=_unknown_if_none(facts.get("known_scam")),
    )

    try:
        text = provider.complete(prompt, MAX_EXPLANATION_TOKENS)
    except LLMError:
        # The verdict does not depend on this call, so degrade the wording
        # rather than failing a safety check over a third-party outage.
        return {"explanation": UNDECODED_EXPLANATION, "source": "unavailable"}

    return {"explanation": _first_sentence(text), "source": "model"}


# ---------------------------------------------------------------------------
# Step 3: Combine scoring + explanation into one analysis
# ---------------------------------------------------------------------------

def analyze(provider: LLMProvider | None, facts: dict) -> dict:
    """
    Full analyzer pipeline: facts (from scanner.py) -> score -> band ->
    recommendation + explanation.

    `provider` may be None; every decoded transaction is explained from the
    facts alone, so the checker still works with no model configured.
    """
    score = compute_risk_score(facts)
    band = score_to_band(score)
    result = explain_transaction(provider, facts)

    return {
        "score": score,
        "band": band,
        "explanation": result["explanation"],
        "recommendation": BAND_RECOMMENDATION[band],
        "explanation_source": result["source"],
        "facts": facts,
    }


# ---------------------------------------------------------------------------
# Quick manual test -- for a real end-to-end test, use tests/test_transactions.py
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import os

    from web3 import Web3

    from llm import get_provider
    from scanner import scan_transaction

    w3 = Web3(Web3.HTTPProvider(os.environ.get("ARC_RPC_URL", "")))
    provider = get_provider()

    tx_hash = "<REAL_TX_HASH_HERE>"
    tx = w3.eth.get_transaction(tx_hash)

    facts = scan_transaction(w3, tx["to"], tx["input"])
    result = analyze(provider, facts)
    print(result)
