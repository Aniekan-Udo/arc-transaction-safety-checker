"""
app.py

Minimal API layer. One route: given a transaction hash, run it through
scanner.py (decode + heuristics) and analyzer.py (score + explanation),
and return the combined result as JSON.

Run with:
    uvicorn app:app --reload --port 8000
"""

import os

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from web3 import Web3

import registry
from analyzer import analyze
from llm import LLMError, get_provider
from scanner import scan_transaction

load_dotenv()

ARC_RPC_URL = os.environ.get("ARC_RPC_URL", "")

# The attester whose on-chain verdicts this deployment vouches for. Writes to
# the registry are permissionless, so an attestation is only meaningful
# relative to who signed it -- see contracts/VerdictRegistry.sol.
ARC_ATTESTER_ADDRESS = os.environ.get("ARC_ATTESTER_ADDRESS", "")

w3 = Web3(Web3.HTTPProvider(ARC_RPC_URL))

# The explanation layer is optional. Every transaction we can decode is
# explained from the verified facts themselves, so a missing or misconfigured
# provider costs wording on undecodable calls -- it does not take the safety
# checker down, and it cannot change a verdict.
try:
    llm = get_provider()
except LLMError as exc:
    print(f"WARNING: {exc} Continuing with rule-based explanations only.")
    llm = None

app = FastAPI(title="Arc Transaction Safety Checker")

# Allow the frontend to call this API. Tighten allow_origins to your real
# frontend's deployed domain once this goes beyond local development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class CheckRequest(BaseModel):
    tx_hash: str


class CheckCalldataRequest(BaseModel):
    """
    A transaction that has not been signed yet: the contract being called and
    the calldata about to be sent to it, exactly as a wallet shows them
    before you confirm.
    """

    to: str
    # Omitted or "0x" means a plain value transfer with no contract call.
    data: str = "0x"


class CheckResponse(BaseModel):
    score: int
    band: str
    explanation: str
    recommendation: str
    # Where the wording came from: "rules", "model", or "unavailable".
    # The verdict is rule-based regardless -- this says how it was phrased.
    explanation_source: str
    facts: dict
    # The matching on-chain attestation, if this verdict has been published
    # to the VerdictRegistry on Arc. None when it has not been -- absence is
    # never evidence that a transaction is safe.
    attestation: dict | None = None


@app.post("/check", response_model=CheckResponse)
def check_transaction(request: CheckRequest):
    if not w3.is_connected():
        raise HTTPException(status_code=503, detail="Not connected to Arc RPC")

    try:
        tx = w3.eth.get_transaction(request.tx_hash)
    except Exception:
        raise HTTPException(status_code=404, detail="Transaction not found on Arc")

    if tx["to"] is None:
        # Contract-creation transactions have no `to` address -- out of
        # scope for this checker, which is about calls to existing contracts.
        raise HTTPException(
            status_code=400,
            detail="This is a contract-creation transaction, not a call -- unsupported for now",
        )

    facts = scan_transaction(w3, tx["to"], tx["input"])
    result = analyze(llm, facts)

    # Read-only lookup. The API holds no key and cannot publish -- see
    # scripts/attest.py -- so this only ever reports what is already on Arc.
    result["attestation"] = registry.read_verdict(
        w3, request.tx_hash, ARC_ATTESTER_ADDRESS
    )
    return result


@app.post("/check-calldata", response_model=CheckResponse)
def check_calldata(request: CheckCalldataRequest):
    """
    Check a transaction *before* it is signed.

    POST /check needs a transaction hash, which only exists once a
    transaction has been signed and broadcast -- by then the approval you
    were worried about has already been granted. This route takes the
    unsigned call instead: the `to` address and the calldata a wallet is
    about to ask you to confirm.

    Nothing here touches the chain's transaction history, so there is no
    attestation to report: a call that has not happened cannot have been
    attested. The field stays null rather than being omitted, so the two
    routes return the same shape.
    """
    if not w3.is_connected():
        raise HTTPException(status_code=503, detail="Not connected to Arc RPC")

    try:
        to_address = Web3.to_checksum_address(request.to)
    except Exception:
        raise HTTPException(
            status_code=400, detail=f"{request.to!r} is not a valid address"
        )

    data = request.data or "0x"
    if not data.startswith("0x"):
        data = "0x" + data
    try:
        # Reject malformed calldata here rather than letting it fall through
        # to the decoder, where it would be indistinguishable from calldata
        # we simply do not recognise -- and so would score MEDIUM as though
        # it were a real unknown call.
        bytes.fromhex(data[2:])
    except ValueError:
        raise HTTPException(status_code=400, detail="`data` is not valid hex")

    facts = scan_transaction(w3, to_address, data)
    result = analyze(llm, facts)
    result["attestation"] = None
    return result


@app.get("/health")
def health():
    return {
        "connected_to_arc": w3.is_connected(),
        "chain_id": w3.eth.chain_id if w3.is_connected() else None,
        "llm_provider": llm.name if llm else None,
        "model": llm.model if llm else None,
        "registry_address": registry.REGISTRY_ADDRESS or None,
        "attester_address": ARC_ATTESTER_ADDRESS or None,
    }


@app.get("/attestations/{tx_hash}")
def get_attestation(tx_hash: str):
    """
    What this deployment's attester published on Arc about `tx_hash`.

    Read-only and keyless. 404 means no attestation exists -- it does not
    mean the transaction is safe.
    """
    if not w3.is_connected():
        raise HTTPException(status_code=503, detail="Not connected to Arc RPC")

    attestation = registry.read_verdict(w3, tx_hash, ARC_ATTESTER_ADDRESS)
    if attestation is None:
        raise HTTPException(
            status_code=404,
            detail="No on-chain attestation for this transaction from this attester",
        )
    return attestation
