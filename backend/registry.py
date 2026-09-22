"""
registry.py

The on-chain side of ArcGuard: compiling, reading and writing the
VerdictRegistry contract deployed on Arc mainnet.

Split deliberately along the trust boundary:

    read_verdict()      -- needs no key, used by the API
    build_attest_tx()   -- builds an unsigned transaction
    (signing)           -- happens only in scripts/attest.py

The API imports the read path and nothing else. It holds no private key and
signs nothing, which keeps the claim in the README honest: the service that
tells you whether a transaction is safe cannot itself move funds.
"""

import json
import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from web3 import Web3

load_dotenv()


CONTRACT_PATH = Path(__file__).resolve().parent.parent / "contracts" / "VerdictRegistry.sol"
BUILD_PATH = Path(__file__).resolve().parent.parent / "contracts" / "VerdictRegistry.json"

SOLC_VERSION = "0.8.24"

# Must match the Band enum's ordering in VerdictRegistry.sol, which in turn
# mirrors analyzer.score_to_band. Ordinal, so do not reorder.
BANDS = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

REGISTRY_ADDRESS = os.environ.get("ARC_REGISTRY_ADDRESS", "")


def band_to_index(band: str) -> int:
    """'MEDIUM' -> 2. Raises rather than defaulting: silently writing the
    wrong band on chain is unfixable, since records are append-only."""
    try:
        return BANDS.index(band)
    except ValueError as exc:
        raise ValueError(f"Unknown band {band!r}. Expected one of {BANDS}.") from exc


def index_to_band(index: int) -> str:
    """2 -> 'MEDIUM'."""
    return BANDS[index]


def compile_contract() -> dict:
    """
    Compile VerdictRegistry.sol and cache the artifact next to it.

    Writing the artifact to disk means the API and the deploy script share
    one ABI, and that the API can read the registry without solc installed --
    it only needs the ABI, not the compiler.
    """
    import solcx

    if SOLC_VERSION not in [str(v) for v in solcx.get_installed_solc_versions()]:
        solcx.install_solc(SOLC_VERSION)

    compiled = solcx.compile_files(
        [str(CONTRACT_PATH)],
        output_values=["abi", "bin"],
        solc_version=SOLC_VERSION,
        optimize=True,
    )

    key = next(k for k in compiled if k.endswith(":VerdictRegistry"))
    artifact = {"abi": compiled[key]["abi"], "bin": compiled[key]["bin"]}

    BUILD_PATH.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    return artifact


@lru_cache(maxsize=1)
def load_artifact() -> dict:
    """The compiled ABI + bytecode, compiling only if it isn't built yet."""
    if BUILD_PATH.exists():
        return json.loads(BUILD_PATH.read_text(encoding="utf-8"))
    return compile_contract()


def get_contract(w3: Web3, address: str | None = None):
    """A bound contract instance, or None if no registry address is set."""
    address = address or REGISTRY_ADDRESS
    if not address:
        return None
    return w3.eth.contract(
        address=Web3.to_checksum_address(address),
        abi=load_artifact()["abi"],
    )


def read_verdict(w3: Web3, tx_hash: str, attester: str) -> dict | None:
    """
    What `attester` published on chain about `tx_hash`, or None if they
    never did (or no registry is configured).

    Read-only, keyless. Returns None rather than a zero-valued record: an
    absent attestation must never read as "score 0, SAFE".
    """
    contract = get_contract(w3)
    if contract is None or not attester:
        return None

    try:
        found, score, band, timestamp = contract.functions.verdictOf(
            Web3.to_bytes(hexstr=tx_hash),
            Web3.to_checksum_address(attester),
        ).call()
    except Exception:
        # An unreachable or wrong-chain registry must not fail a safety
        # check -- the verdict itself does not depend on this.
        return None

    if not found:
        return None

    return {
        "score": score,
        "band": index_to_band(band),
        "timestamp": timestamp,
        "attester": Web3.to_checksum_address(attester),
    }


def build_attest_tx(w3: Web3, account_address: str, tx_hash: str, score: int, band: str) -> dict:
    """
    Build the unsigned `attest()` transaction. Signing is the caller's job,
    and deliberately does not happen in this module.
    """
    contract = get_contract(w3)
    if contract is None:
        raise RuntimeError(
            "ARC_REGISTRY_ADDRESS is not set -- deploy the registry first "
            "(python -m scripts.deploy_registry)."
        )

    account_address = Web3.to_checksum_address(account_address)
    return contract.functions.attest(
        Web3.to_bytes(hexstr=tx_hash),
        score,
        band_to_index(band),
    ).build_transaction(
        {
            "from": account_address,
            "nonce": w3.eth.get_transaction_count(account_address),
            "chainId": w3.eth.chain_id,
        }
    )
