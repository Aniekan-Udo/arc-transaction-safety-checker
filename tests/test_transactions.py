"""
test_transactions.py

A small, manual sanity-check harness -- not a full pytest suite.
Run this before you trust the scoring.

The hashes below are real Arc MAINNET transactions (chain 5042), found by
scanning recent blocks and verified against this pipeline. They are not
invented. Public Arc nodes prune old history, so they will eventually stop
resolving -- rescan recent blocks and replace them when that happens.

Note that unlimited approvals are not rare on Arc: a scan of 300 consecutive
mainnet blocks found 38 of them among 87 approve() calls.

On mainnet contract_age_hours is always None, because explorer.arc.io serves
/api behind a Cloudflare bot challenge. The fresh_contract signal therefore
never fires and an unlimited approval tops out at MEDIUM (35) rather than
HIGH (60). That is correct behaviour, not a bug -- the tool reports what it
could not verify instead of guessing.

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
        "label": "Plain transfer (expect: SAFE 0, is_plain_transfer=True)",
        "tx_hash": "0x42743ee39ad74060cfe1634b22c6e3a941cb45aea2892b77b5fce4c8900547a4",
    },
    {
        "label": "Bounded approval (expect: SAFE 0, unlimited_approval=False)",
        "tx_hash": "0x446fc48beb8eecc76d2f853a81e39a5cca1fcc8e38159038f25c2d2260c08d89",
    },
    {
        # MEDIUM, not HIGH: fresh_contract cannot fire on mainnet (no explorer
        # API), so the unlimited-approval weight stands alone. With contract
        # age available, an unlimited approval to a contract under 24h old
        # would score 60 / HIGH.
        "label": "Unlimited approval (expect: MEDIUM 35, unlimited_approval=True)",
        "tx_hash": "0xddbcda238923133abd1669693b4d82185e1182c3b6904c93b5a78ba5865598cb",
    },
    {
        # Calldata we cannot decode is penalised, never treated as safe:
        # not knowing what you are authorising is its own risk.
        "label": "Undecodable call (expect: MEDIUM 35, function=None)",
        "tx_hash": "0x5b279ad0a75527c0c78fb610e1e3fb45303ea1fc74349107dd1d8e7e5cbf0248",
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
