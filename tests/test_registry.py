"""
test_registry.py

Tests VerdictRegistry.sol -- no network, no gas, no deployed contract.

Unlike tests/test_transactions.py (a manual harness that reads live chain
data and prints results for a human), this one asserts. Contract behaviour
is fixed at deploy time and records are append-only, so a mistake here is
permanent: worth testing before it reaches Arc rather than after.

Two tiers:

  Offline checks   always run. Compilation, the ABI surface, and the band
                   mapping shared between Solidity and Python.
  EVM checks       run only if eth-tester is importable, exercising the
                   deployed contract's actual behaviour on a local chain.

eth-tester needs py-evm, which needs a C toolchain to build on some
platforms (notably Python 3.14 on Windows without MSVC build tools). Rather
than make the whole file unrunnable there, the EVM tier is skipped and says
so. Install it with:

    pip install "eth-tester[py-evm]"

Run with (from the project root):
    python -m tests.test_registry
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from web3 import Web3

import registry

try:
    import eth_tester  # noqa: F401

    HAS_EVM = True
except ImportError:
    HAS_EVM = False

TX_A = "0x" + "11" * 32
TX_B = "0x" + "22" * 32


def deploy(w3):
    artifact = registry.load_artifact()
    contract = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bin"])
    tx_hash = contract.constructor().transact({"from": w3.eth.accounts[0]})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return w3.eth.contract(address=receipt["contractAddress"], abi=artifact["abi"])


def check(label, actual, expected):
    status = "PASS" if actual == expected else "FAIL"
    print(f"  [{status}] {label}: got {actual!r}, expected {expected!r}")
    return actual == expected


def run_offline_checks(results):
    """Checks that need no EVM: the artifact, the ABI, and the band mapping."""
    print("--- the contract compiles and exposes the expected surface ---")
    artifact = registry.load_artifact()
    names = {f["name"] for f in artifact["abi"] if f["type"] == "function"}
    results.append(check("attest() present", "attest" in names, True))
    results.append(check("verdictOf() present", "verdictOf" in names, True))
    results.append(check("bytecode is non-empty", len(artifact["bin"]) > 0, True))

    events = [f["name"] for f in artifact["abi"] if f["type"] == "event"]
    results.append(check("VerdictAttested emitted", events, ["VerdictAttested"]))

    print("\n--- verdictOf returns a found flag, not just a score ---")
    verdict_of = next(f for f in artifact["abi"] if f.get("name") == "verdictOf")
    outputs = [o["name"] for o in verdict_of["outputs"]]
    # Without this flag an unattested transaction reads as score 0 / SAFE,
    # which is the exact false negative this tool exists to prevent.
    results.append(check("first output is 'found'", outputs[0], "found"))
    results.append(check("outputs", outputs, ["found", "score", "band", "timestamp"]))

    print("\n--- Solidity's Band enum and analyzer.py's bands agree ---")
    from analyzer import score_to_band

    # score_to_band is the only place bands are produced, so every value it
    # can return must map onto the enum. A mismatch would publish a wrong
    # band on chain, permanently.
    produced = {score_to_band(n) for n in range(0, 101)}
    results.append(check("every producible band is known", produced <= set(registry.BANDS), True))
    for index, name in enumerate(registry.BANDS):
        results.append(
            check(f"{name} -> {index} -> {name}", registry.index_to_band(index), name)
        )
    try:
        registry.band_to_index("DEFINITELY_NOT_A_BAND")
        results.append(check("unknown band raises", False, True))
    except ValueError:
        results.append(check("unknown band raises", True, True))

    print("\n--- an unset registry reads as no attestation, never as safe ---")
    saved = registry.REGISTRY_ADDRESS
    registry.REGISTRY_ADDRESS = ""
    try:
        results.append(
            check("read_verdict with no registry", registry.read_verdict(None, TX_A, ""), None)
        )
    finally:
        registry.REGISTRY_ADDRESS = saved


def run_evm_checks(results):
    w3 = Web3(__import__("web3").EthereumTesterProvider())
    alice, bob = w3.eth.accounts[0], w3.eth.accounts[1]
    contract = deploy(w3)

    print("Deployed VerdictRegistry to a local test chain")

    print("\n--- an unattested transaction is not reported as safe ---")
    found, score, band, _ = contract.functions.verdictOf(
        Web3.to_bytes(hexstr=TX_A), alice
    ).call()
    results.append(check("found", found, False))
    # The trap this guards: score 0 / band 0 is a valid SAFE verdict, so
    # callers must read `found` rather than trusting the zero value.
    results.append(check("score defaults to 0 (must not be trusted)", score, 0))
    results.append(check("band defaults to 0 == SAFE", band, 0))

    print("\n--- a published verdict reads back intact ---")
    contract.functions.attest(
        Web3.to_bytes(hexstr=TX_A), 35, registry.band_to_index("MEDIUM")
    ).transact({"from": alice})
    found, score, band, timestamp = contract.functions.verdictOf(
        Web3.to_bytes(hexstr=TX_A), alice
    ).call()
    results.append(check("found", found, True))
    results.append(check("score", score, 35))
    results.append(check("band", registry.index_to_band(band), "MEDIUM"))
    results.append(check("timestamp is set", timestamp > 0, True))
    results.append(check("total", contract.functions.total().call(), 1))
    results.append(
        check("attestationCount[alice]", contract.functions.attestationCount(alice).call(), 1)
    )

    print("\n--- records are append-only: re-attesting reverts ---")
    try:
        contract.functions.attest(
            Web3.to_bytes(hexstr=TX_A), 0, registry.band_to_index("SAFE")
        ).transact({"from": alice})
        results.append(check("re-attest reverted", False, True))
    except Exception:
        results.append(check("re-attest reverted", True, True))
    results.append(
        check("verdict unchanged after failed overwrite",
              contract.functions.verdictOf(Web3.to_bytes(hexstr=TX_A), alice).call()[1], 35)
    )

    print("\n--- one attester cannot forge or overwrite another's verdict ---")
    contract.functions.attest(
        Web3.to_bytes(hexstr=TX_A), 0, registry.band_to_index("SAFE")
    ).transact({"from": bob})
    alice_score = contract.functions.verdictOf(Web3.to_bytes(hexstr=TX_A), alice).call()[1]
    bob_score = contract.functions.verdictOf(Web3.to_bytes(hexstr=TX_A), bob).call()[1]
    results.append(check("alice's verdict still 35", alice_score, 35))
    results.append(check("bob's own verdict is 0", bob_score, 0))
    results.append(check("total counts both", contract.functions.total().call(), 2))

    print("\n--- an impossible score is rejected ---")
    try:
        contract.functions.attest(
            Web3.to_bytes(hexstr=TX_B), 101, registry.band_to_index("CRITICAL")
        ).transact({"from": alice})
        results.append(check("score > 100 reverted", False, True))
    except Exception:
        results.append(check("score > 100 reverted", True, True))

    print("\n--- the event carries the verdict ---")
    receipt = w3.eth.wait_for_transaction_receipt(
        contract.functions.attest(
            Web3.to_bytes(hexstr=TX_B), 70, registry.band_to_index("CRITICAL")
        ).transact({"from": alice})
    )
    logs = contract.events.VerdictAttested().process_receipt(receipt)
    results.append(check("one event emitted", len(logs), 1))
    results.append(check("event score", logs[0]["args"]["score"], 70))
    results.append(check("event attester", logs[0]["args"]["attester"], alice))


def run_tests() -> int:
    results = []
    run_offline_checks(results)

    if HAS_EVM:
        print()
        run_evm_checks(results)
    else:
        print(
            "\nSKIPPED the EVM tier: eth-tester is not installed, so the "
            "contract's runtime behaviour was NOT exercised here."
            '\nInstall it with: pip install "eth-tester[py-evm]"'
        )

    passed, total = sum(results), len(results)
    suffix = "" if HAS_EVM else " (offline tier only)"
    print(f"\n{passed}/{total} checks passed{suffix}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(run_tests())
