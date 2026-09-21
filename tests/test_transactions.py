"""
test_transactions.py

A small, manual sanity-check harness -- not a full pytest suite.
Run this before you trust the scoring.

The hashes below are real Arc TESTNET transactions (chain 5042002), found by
scanning recent blocks and verified against this pipeline. They are not
invented. They will age out of relevance as the chain moves on -- replace
them with fresher ones when the expectations below stop matching, and note
that they resolve only while .env points at testnet.

Note that unlimited approvals are not rare on Arc: a scan of 300 consecutive
mainnet blocks found 38 of them among 87 approve() calls.

Run with (from the project root):
    python -m tests.test_transactions
"""

import os
import sys

# Allow importing from backend/ when running this script directly.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from dotenv import load_dotenv
from web3 import Web3

from analyzer import analyze
from llm import LLMError, get_provider
from scanner import scan_transaction

load_dotenv()

TEST_CASES = [
    {
        "label": "Plain transfer (expect: SAFE, is_plain_transfer=True)",
        "tx_hash": "0xfe6e656aa197070870c700c7dfa370a1fabe64b1eca6694579505cb250f49560",
    },
    {
        "label": "Bounded approval (expect: SAFE, unlimited_approval=False)",
        "tx_hash": "0xa823199977b7478c04a2676e228ece99207fe6f02e16ad139d703741f5c0f6e4",
    },
    {
        # MEDIUM, not HIGH: the spender is an established contract, so the
        # fresh-contract signal that compounds with an unlimited approval
        # does not fire. Both together are what produce HIGH (60).
        "label": "Unlimited approval (expect: MEDIUM, unlimited_approval=True)",
        "tx_hash": "0xd32d674a93a281fda79bdfeda05f5302321a68b7ccaaf83cfade52861ce39200",
    },
]


def run_tests():
    w3 = Web3(Web3.HTTPProvider(os.environ.get("ARC_RPC_URL", "")))

    if not w3.is_connected():
        print("ERROR: could not connect to Arc RPC. Check ARC_RPC_URL in your .env file.")
        return

    try:
        provider = get_provider()
        print(f"Explanation provider: {provider.name} ({provider.model})")
    except LLMError as exc:
        provider = None
        print(f"No explanation provider ({exc}) -- rule-based wording only.")

    for case in TEST_CASES:
        print(f"\n--- {case['label']} ---")

        if case["tx_hash"].startswith("<"):
            print("SKIPPED -- placeholder hash not yet filled in.")
            continue

        try:
            tx = w3.eth.get_transaction(case["tx_hash"])
        except Exception as e:
            print(f"FAILED to fetch transaction: {e}")
            continue

        facts = scan_transaction(w3, tx["to"], tx["input"])
        result = analyze(provider, facts)

        print(f"Function:            {facts['function']}")
        print(f"Counterparty:        {facts['counterparty']}")
        print(f"Unlimited approval:  {facts['unlimited_approval']}")
        print(f"Contract age (hrs):  {facts['contract_age_hours']}")
        print(f"Known scam:          {facts['known_scam']}")
        print(f"Score / Band:        {result['score']} / {result['band']}")
        print(f"Explanation:         {result['explanation']}")
        print(f"Wording from:        {result['explanation_source']}")
        print(f"Recommendation:      {result['recommendation']}")

        # Manual review reminder -- false negatives here are the failure
        # mode that matters most for a safety tool like this.
        print(">> Manually verify this result matches what you expect before trusting it.")


if __name__ == "__main__":
    run_tests()
