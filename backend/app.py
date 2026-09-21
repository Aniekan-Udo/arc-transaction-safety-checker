"""
app.py

Minimal API layer. One route: given a transaction hash, run it through
scanner.py (decode + heuristics) and analyzer.py (score + explanation),
and return the combined result as JSON.

Run with:
    uvicorn app:app --reload --port 8000

In production (Render) the same process also serves frontend/index.html, so
the page and the API share an origin and no API base URL has to be configured.
"""

import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from web3 import Web3

from analyzer import analyze
from llm import LLMError, get_provider
from scanner import scan_transaction

load_dotenv()

ARC_RPC_URL = os.environ.get("ARC_RPC_URL", "")

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


class CheckResponse(BaseModel):
    score: int
    band: str
    explanation: str
    recommendation: str
    # Where the wording came from: "rules", "model", or "unavailable".
    # The verdict is rule-based regardless -- this says how it was phrased.
    explanation_source: str
    facts: dict


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
    return analyze(llm, facts)


@app.get("/health")
def health():
    return {
        "connected_to_arc": w3.is_connected(),
        "llm_provider": llm.name if llm else None,
        "model": llm.model if llm else None,
    }


# Serve the frontend from this same process. Mounted last so it only catches
# paths the API routes above did not claim. html=True makes "/" return
# index.html.
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
if FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
else:
    print(f"WARNING: no frontend directory at {FRONTEND_DIR}; serving API only.")
