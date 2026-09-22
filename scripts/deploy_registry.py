"""
deploy_registry.py

Deploy VerdictRegistry.sol to Arc mainnet. Run once.

    python -m scripts.deploy_registry

Needs ATTESTER_PRIVATE_KEY in .env, funded with a small amount of USDC --
Arc pays gas in USDC. Prints the deployed address; put it in .env as
ARC_REGISTRY_ADDRESS.

This script is the only place besides scripts/attest.py that touches a
private key. The API never imports it.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from dotenv import load_dotenv
from eth_account import Account
from web3 import Web3

import registry

load_dotenv()


def main() -> int:
    rpc_url = os.environ.get("ARC_RPC_URL", "")
    private_key = os.environ.get("ATTESTER_PRIVATE_KEY", "")

    if not private_key:
        print("ERROR: ATTESTER_PRIVATE_KEY is not set in .env.")
        return 1

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        print(f"ERROR: could not connect to Arc RPC at {rpc_url!r}.")
        return 1

    account = Account.from_key(private_key)
    chain_id = w3.eth.chain_id
    balance = w3.eth.get_balance(account.address)

    print(f"Network:  chain {chain_id}")
    print(f"Deployer: {account.address}")
    print(f"Balance:  {w3.from_wei(balance, 'ether')} (USDC, Arc pays gas in USDC)")

    if balance == 0:
        print("\nERROR: deployer has no balance. Fund it with a little USDC on Arc.")
        return 1

    print(f"\nCompiling {registry.CONTRACT_PATH.name} with solc {registry.SOLC_VERSION}...")
    artifact = registry.compile_contract()
    print(f"Compiled. Artifact written to {registry.BUILD_PATH}")

    contract = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bin"])
    tx = contract.constructor().build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "chainId": chain_id,
        }
    )

    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"\nDeploying... tx {tx_hash.hex()}")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
    if receipt["status"] != 1:
        print("ERROR: deployment transaction reverted.")
        return 1

    print(f"\nDeployed VerdictRegistry at {receipt['contractAddress']}")
    print(f"Block:    {receipt['blockNumber']}")
    print(f"Gas used: {receipt['gasUsed']}")
    print("\nAdd these to .env (and to your Render environment):")
    print(f"  ARC_REGISTRY_ADDRESS={receipt['contractAddress']}")
    print(f"  ARC_ATTESTER_ADDRESS={account.address}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
