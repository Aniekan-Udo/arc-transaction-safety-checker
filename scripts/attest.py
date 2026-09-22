"""
attest.py

Run a transaction through ArcGuard and publish the verdict to the
VerdictRegistry on Arc mainnet.

    python -m scripts.attest 0x<tx_hash>
    python -m scripts.attest 0x<tx_hash> --dry-run

The verdict published is exactly the one the API would return: this script
calls the same scan_transaction() and analyze() and never recomputes or
adjusts anything. What goes on chain is what the rules decided.

Deliberately a separate command rather than a step inside POST /check:
  - the API stays keyless, so it cannot sign anything, ever;
  - a check is free and instant, while an attestation costs gas and is
    permanent. Those should not be the same action.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from dotenv import load_dotenv
from eth_account import Account
from web3 import Web3

import registry
from analyzer import analyze
from llm import LLMError, get_provider
from scanner import scan_transaction

load_dotenv()


def main() -> int:
    parser = argparse.ArgumentParser(description="Publish an ArcGuard verdict on chain.")
    parser.add_argument("tx_hash", help="the Arc transaction hash to check and attest")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="compute and print the verdict without publishing it",
    )
    args = parser.parse_args()

    w3 = Web3(Web3.HTTPProvider(os.environ.get("ARC_RPC_URL", "")))
    if not w3.is_connected():
        print("ERROR: could not connect to Arc RPC. Check ARC_RPC_URL in .env.")
        return 1

    try:
        tx = w3.eth.get_transaction(args.tx_hash)
    except Exception:
        print(f"ERROR: transaction {args.tx_hash} not found on Arc.")
        return 1

    if tx["to"] is None:
        print("ERROR: contract-creation transactions are out of scope.")
        return 1

    try:
        provider = get_provider()
    except LLMError:
        provider = None

    facts = scan_transaction(w3, tx["to"], tx["input"])
    result = analyze(provider, facts)

    print(f"Transaction: {args.tx_hash}")
    print(f"Verdict:     {result['score']}/100 {result['band']} -- {result['recommendation']}")
    print(f"Explanation: {result['explanation']}")

    if args.dry_run:
        print("\nDry run -- nothing published.")
        return 0

    private_key = os.environ.get("ATTESTER_PRIVATE_KEY", "")
    if not private_key:
        print("\nERROR: ATTESTER_PRIVATE_KEY is not set in .env.")
        return 1

    account = Account.from_key(private_key)

    existing = registry.read_verdict(w3, args.tx_hash, account.address)
    if existing is not None:
        # Records are append-only per attester, so the on-chain call would
        # revert. Say so here rather than burning gas to find out.
        print(
            f"\nAlready attested by {account.address}: "
            f"{existing['score']}/100 {existing['band']}. Nothing to do."
        )
        return 0

    print(f"\nAttesting as {account.address}...")
    unsigned = registry.build_attest_tx(
        w3, account.address, args.tx_hash, result["score"], result["band"]
    )
    signed = account.sign_transaction(unsigned)
    sent = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(sent, timeout=180)

    if receipt["status"] != 1:
        print("ERROR: attestation transaction reverted.")
        return 1

    print(f"Published on Arc. tx {sent.hex()}")
    print(f"Block:    {receipt['blockNumber']}")
    print(f"Gas used: {receipt['gasUsed']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
