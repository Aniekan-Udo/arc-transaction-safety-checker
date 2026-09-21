"""
scanner.py

Core decoding + heuristics engine for the transaction safety checker.

Flow:
    raw transaction (to, data) -> decode the function call via ABI
                               -> run rule-based heuristic checks
                               -> return one structured dict of facts + flags

This module is intentionally deterministic / rule-based, with NO LLM calls.
The plain-language explanation layer (analyzer.py) consumes the output of
this module -- it never re-derives facts on its own. See the project README
("Key Design Decisions") for why this split matters.
"""

import os
import time
from datetime import datetime
from functools import lru_cache

import requests
from dotenv import load_dotenv
from web3 import Web3

load_dotenv()


# ---------------------------------------------------------------------------
# Constants / config
# ---------------------------------------------------------------------------

# Arc's block explorer exposes an Etherscan-compatible API. As of writing,
# Arc's mainnet explorer/API access was listed as permissioned, so you may
# need to request access rather than finding a public endpoint. Set these
# in your .env file (see .env.example).
ARC_EXPLORER_API_BASE = os.environ.get("ARC_EXPLORER_API_BASE", "")
ARC_EXPLORER_API_KEY = os.environ.get("ARC_EXPLORER_API_KEY", "")

# Which chain the explorer above indexes. Checked against the chain the RPC
# actually serves before the explorer is trusted -- see explorer_available().
ARC_EXPLORER_CHAIN_ID = os.environ.get("ARC_EXPLORER_CHAIN_ID", "")

# Arc mainnet chain ID, needed for the GoPlus address-security call.
ARC_CHAIN_ID = os.environ.get("ARC_CHAIN_ID", "5042")

GOPLUS_ADDRESS_SECURITY_URL = "https://api.gopluslabs.io/api/v1/address_security/{address}"

GOPLUS_RISK_FLAGS = [
    "sanctioned", "cybercrime", "money_laundering", "financial_crime",
    "darkweb_transactions", "phishing_activities", "stealing_attack",
    "blacklist_doubt",
]

# Minimal ERC-20 ABI fragments -- just the functions we care about for now.
# Extend this list as you add more function types to detect (see README's
# "Known gaps & next steps").
ERC20_ABI = [
    {
        "name": "approve",
        "type": "function",
        "inputs": [
            {"name": "spender", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
    },
    {
        "name": "transferFrom",
        "type": "function",
        "inputs": [
            {"name": "from", "type": "address"},
            {"name": "to", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
    },
]

# For these functions the address carrying the risk is an argument, not the
# contract being called: approving USDC is only dangerous because of who you
# approve. Functions not listed here fall back to the `to` address.
COUNTERPARTY_PARAM = {"approve": "spender", "transferFrom": "to"}

# The classic "approve forever" value: max uint256.
MAX_UINT256 = 2**256 - 1

# How fresh is "suspiciously fresh" for a contract, in hours.
# Tune this once you have tested against real examples.
FRESH_CONTRACT_THRESHOLD_HOURS = 24

# Fallback list, used only if the GoPlus API call fails. Empty by default --
# populate from a public blocklist if you want an offline fallback.
KNOWN_SCAM_ADDRESSES: set[str] = set()


# ---------------------------------------------------------------------------
# Step 1: Decode the function call
# ---------------------------------------------------------------------------

def normalize_calldata(data: str | bytes) -> str:
    """
    Return `data` as a 0x-prefixed hex string.

    web3 hands back calldata as HexBytes, and hexbytes >= 1.0 (which web3 v7
    pulls in) dropped the 0x prefix from .hex(). Unprefixed data fails ABI
    decoding, which would silently make every transaction look undecodable.
    """
    if isinstance(data, (bytes, bytearray)):
        data = data.hex()
    if not data:
        return "0x"
    return data if data.startswith("0x") else "0x" + data


def decode_function_call(w3: Web3, to_address: str, data: str | bytes) -> dict | None:
    """
    Try to decode the transaction's `data` field against known ABI functions.

    Returns a dict like:
        {"function": "approve", "params": {"spender": "0x...", "amount": ...}}
    or None if the function isn't one we recognize (yet).
    """
    data = normalize_calldata(data)
    if data == "0x":
        # Plain transfer with no contract call -- nothing to decode.
        return None

    contract = w3.eth.contract(address=Web3.to_checksum_address(to_address), abi=ERC20_ABI)

    try:
        func_obj, params = contract.decode_function_input(data)
        return {"function": func_obj.fn_name, "params": params}
    except Exception:
        # Selector doesn't match anything in our ABI fragment.
        # Be explicit about this rather than silently returning "safe".
        return None


def counterparty_address(decoded: dict | None, to_address: str) -> str:
    """
    The address whose age and reputation actually matter for this call.

    For an approval that is the spender being granted access, not the token
    contract -- the token is usually a legitimate one, and checking it instead
    is how an unlimited approval to a brand-new scam contract reads as clean.
    """
    if decoded:
        param = COUNTERPARTY_PARAM.get(decoded["function"])
        if param:
            return decoded["params"][param]
    return to_address


# ---------------------------------------------------------------------------
# Step 2: Heuristic checks (each one is independent and easy to test alone)
# ---------------------------------------------------------------------------

def check_unlimited_approval(decoded: dict | None) -> bool:
    """True if this is an approve() call granting the max possible amount."""
    if not decoded or decoded["function"] != "approve":
        return False
    return decoded["params"].get("amount") == MAX_UINT256


@lru_cache(maxsize=4)
def _chain_id(w3: Web3) -> int:
    """Cached: the chain the RPC is actually serving."""
    return w3.eth.chain_id


def explorer_available(rpc_chain_id: int) -> bool:
    """
    Whether the configured explorer may be trusted for this chain.

    ARC_EXPLORER_CHAIN_ID must state which chain the explorer indexes, and it
    has to match the chain the RPC is serving. Pointing a testnet explorer at
    mainnet addresses is not merely useless: addresses collide across chains
    (same deployer and nonce, or CREATE2 -- measured at 2 of 11 sampled Arc
    mainnet contracts), so it can return a creation date for a *different*
    contract that happens to share the address. A brand-new scam contract
    would then look established, `fresh_contract` would not fire, and a HIGH
    verdict would quietly become MEDIUM.

    Every other failure in this system fails closed; this one would fail
    open, so an unset or mismatched chain id disables the explorer rather
    than guessing.
    """
    if not ARC_EXPLORER_API_BASE or not ARC_EXPLORER_CHAIN_ID:
        return False
    return ARC_EXPLORER_CHAIN_ID.strip() == str(rpc_chain_id)


def explorer_api_url(base: str) -> str:
    """
    Build the explorer's API endpoint from ARC_EXPLORER_API_BASE.

    Accepts the base with or without a trailing "/api": pasting the full
    ".../api" URL is the natural mistake, and the resulting ".../api/api"
    would fail silently into "couldn't verify contract age" forever rather
    than complaining. Fail loudly or not at all -- not quietly.
    """
    base = base.rstrip("/")
    return base if base.endswith("/api") else f"{base}/api"


# Deployment times never change, so a successful lookup is cached for the
# life of the process. Only successes are stored: caching a failure would let
# one rate-limited request disable this signal for an address permanently.
_CREATION_TIMESTAMPS: dict[str, int] = {}


def _creation_timestamp(w3: Web3, address: str) -> int | None:
    """
    When this contract was deployed, as a unix timestamp, or None if the
    explorer could not tell us.

    Every check hits the explorer, and Arc's testnet explorer rate-limits
    (HTTP 429). Without caching, a burst of traffic silently turns the
    contract-age signal off -- quietly downgrading HIGH verdicts to MEDIUM
    exactly when the tool is busiest.
    """
    key = address.lower()
    if key in _CREATION_TIMESTAMPS:
        return _CREATION_TIMESTAMPS[key]

    for lookup in (_creation_via_etherscan_api, _creation_via_blockscout_v2):
        try:
            timestamp = lookup(w3, address)
        except Exception:
            # Rate limit, address not indexed, explorer down, unexpected
            # shape. Try the next source; if none work the caller gets None
            # and treats it as "couldn't verify", never as "safe".
            continue
        if timestamp is not None:
            _CREATION_TIMESTAMPS[key] = timestamp
            return timestamp

    return None


def _creation_via_etherscan_api(w3: Web3, address: str) -> int | None:
    """
    The portable path: the Etherscan-compatible `getcontractcreation` action,
    which any such explorer supports. Preferred because it is one request and
    usually carries the timestamp outright.
    """
    response = requests.get(
        explorer_api_url(ARC_EXPLORER_API_BASE),
        params={
            "module": "contract",
            "action": "getcontractcreation",
            "contractaddresses": address,
            "apikey": ARC_EXPLORER_API_KEY,
        },
        timeout=5,
    )
    response.raise_for_status()
    result = response.json()["result"][0]

    timestamp = result.get("timestamp")
    if timestamp is None:
        # Not every Etherscan-compatible explorer returns a timestamp here --
        # fall back to the block the creation tx landed in.
        receipt = w3.eth.get_transaction_receipt(result["txHash"])
        timestamp = w3.eth.get_block(receipt["blockNumber"])["timestamp"]

    return int(timestamp)


def _creation_via_blockscout_v2(w3: Web3, address: str) -> int | None:
    """
    Blockscout-specific fallback, for when the compatible API is unavailable.

    Arc's testnet explorer throttles the Etherscan-compatible /api to 10
    requests per ~17 minutes while leaving its native /api/v2 unthrottled,
    which otherwise makes contract age unusable in a burst.

    Two requests, both to the explorer: v2 gives the creation transaction
    but no time, and the transaction carries the timestamp. Deliberately
    does not ask the RPC for that transaction -- public Arc nodes prune old
    history, so a contract deployed millions of blocks ago reads as
    "transaction not found" there. `w3` is unused, kept for the shared
    lookup signature. Harmless against non-Blockscout explorers: the
    request fails and the caller moves on.
    """
    base = explorer_api_url(ARC_EXPLORER_API_BASE).removesuffix("/api")

    address_response = requests.get(f"{base}/api/v2/addresses/{address}", timeout=5)
    address_response.raise_for_status()
    tx_hash = address_response.json().get("creation_transaction_hash")
    if not tx_hash:
        return None

    tx_response = requests.get(f"{base}/api/v2/transactions/{tx_hash}", timeout=5)
    tx_response.raise_for_status()
    timestamp = tx_response.json().get("timestamp")
    if not timestamp:
        return None

    return int(datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp())


def check_contract_age_hours(w3: Web3, address: str) -> float | None:
    """
    Return how many hours ago this address's contract was deployed,
    or None if we can't determine it (not a contract, or the lookup fails).

    get_code() only tells you *whether* it's a contract -- for *when* it
    was deployed, we use Arc's Etherscan-compatible explorer API via the
    standard `getcontractcreation` action.
    """
    code = w3.eth.get_code(Web3.to_checksum_address(address))
    if code in (b"", b"0x"):
        return None  # Not a contract at all -- just a regular wallet.

    if not explorer_available(_chain_id(w3)):
        # Not configured, or configured for a different chain than the RPC
        # is serving. Either way we cannot verify -- see .env.example.
        return None

    timestamp = _creation_timestamp(w3, address)
    if timestamp is None:
        return None

    return (time.time() - timestamp) / 3600


def check_known_scam_address(address: str) -> bool | None:
    """
    Whether GoPlus flags this address for malicious activity (sanctions,
    phishing, stealing attacks, scam-token creation, etc).

    Returns True (flagged), False (checked and clean), or None when the check
    could not run -- an unsupported chain or a network error. Callers must
    treat None as "unverified", never as "clean".

    KNOWN_SCAM_ADDRESSES is consulted first, so it still works as an offline
    fallback when the API is unavailable.
    """
    if address.lower() in KNOWN_SCAM_ADDRESSES:
        return True

    try:
        response = requests.get(
            GOPLUS_ADDRESS_SECURITY_URL.format(address=address),
            params={"chain_id": ARC_CHAIN_ID},
            timeout=5,
        )
        response.raise_for_status()
        payload = response.json()

        # GoPlus reports per-request failures in the body rather than the
        # status code (code 1 means success). An unsupported chain lands here.
        if payload.get("code") != 1:
            return None

        data = payload.get("result") or {}
        return any(data.get(flag) in (True, "1") for flag in GOPLUS_RISK_FLAGS)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Step 3: Combine everything into one scan
# ---------------------------------------------------------------------------

def scan_transaction(w3: Web3, to_address: str, data: str | bytes) -> dict:
    """
    Run the full decode + heuristics pipeline on a single transaction.

    Returns a structured dict, e.g.:
        {
            "to": "0x...",
            "function": "approve",
            "params": {...},
            "is_plain_transfer": False,
            "selector": "0x095ea7b3",
            "counterparty": "0x...",
            "unlimited_approval": True,
            "contract_age_hours": 2.0,
            "known_scam": False,
        }

    `counterparty` is the address the age and reputation checks were run
    against -- see counterparty_address().

    This dict is what gets passed to analyzer.py -- the LLM there only
    ever explains these facts, never re-derives them.
    """
    decoded = decode_function_call(w3, to_address, data)
    counterparty = counterparty_address(decoded, to_address)
    calldata = normalize_calldata(data)

    return {
        "to": to_address,
        "function": decoded["function"] if decoded else None,
        "params": decoded["params"] if decoded else None,
        # No calldata at all is a plain value transfer -- fully understood,
        # unlike calldata we failed to decode. Keep the two apart so only
        # the genuinely unverified case is penalised.
        "is_plain_transfer": calldata == "0x",
        # The four-byte function signature: the only thing identifying a call
        # we could not decode. Carried for debugging and for analyzer.py.
        "selector": calldata[:10] if len(calldata) >= 10 else None,
        "counterparty": counterparty,
        "unlimited_approval": check_unlimited_approval(decoded),
        "contract_age_hours": check_contract_age_hours(w3, counterparty),
        "known_scam": check_known_scam_address(counterparty),
    }


# ---------------------------------------------------------------------------
# Quick manual test -- for a real end-to-end test, use tests/test_transactions.py
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    w3 = Web3(Web3.HTTPProvider(os.environ.get("ARC_RPC_URL", "")))

    tx_hash = "<REAL_TX_HASH_HERE>"
    tx = w3.eth.get_transaction(tx_hash)

    result = scan_transaction(w3, tx["to"], tx["input"])
    print(result)
