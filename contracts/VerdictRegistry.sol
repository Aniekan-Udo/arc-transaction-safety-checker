// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ArcGuard VerdictRegistry
/// @notice An on-chain, append-only record of ArcGuard safety verdicts for
///         Arc transactions.
///
/// Why this exists: ArcGuard's verdicts are produced off-chain by
/// deterministic rules. Publishing them here makes a verdict citable and
/// timestamped by Arc itself -- "this tool said MEDIUM about this
/// transaction, at this block" becomes a fact anyone can verify without
/// trusting the API to report its own history honestly.
///
/// Trust model: writes are permissionless by design. Anyone may attest to
/// anything, so an attestation means nothing on its own -- it means
/// something relative to *who* signed it. Records are therefore keyed by
/// (txHash, attester), so no one can overwrite or forge another attester's
/// verdict. Consumers filter by the attester address they trust.
///
/// The ArcGuard API never writes here. It holds no key and signs nothing;
/// publishing is a separate, explicitly-invoked step (scripts/attest.py).
contract VerdictRegistry {
    /// @dev Mirrors analyzer.py's bands. Ordinal, so ordering is meaningful.
    enum Band {
        SAFE,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    struct Attestation {
        uint8 score; // 0-100, as computed by analyzer.compute_risk_score
        Band band;
        uint64 timestamp; // block time the attestation landed
        bool exists; // distinguishes "score 0 / SAFE" from "never attested"
    }

    /// @notice txHash => attester => the verdict that attester published.
    mapping(bytes32 => mapping(address => Attestation)) private _attestations;

    /// @notice How many attestations this registry has recorded in total.
    uint256 public total;

    /// @notice How many attestations a given address has published.
    mapping(address => uint256) public attestationCount;

    event VerdictAttested(
        bytes32 indexed txHash,
        address indexed attester,
        uint8 score,
        Band band,
        uint64 timestamp
    );

    error InvalidScore(uint8 score);
    error AlreadyAttested(bytes32 txHash, address attester);

    /// @notice Publish a verdict for `txHash`.
    /// @dev Append-only per attester: re-attesting the same transaction
    ///      reverts rather than silently rewriting history, which is the
    ///      whole point of putting it on chain. A changed verdict is a new
    ///      attester or a new registry, never an edited record.
    function attest(bytes32 txHash, uint8 score, Band band) external {
        if (score > 100) revert InvalidScore(score);
        if (_attestations[txHash][msg.sender].exists) {
            revert AlreadyAttested(txHash, msg.sender);
        }

        _attestations[txHash][msg.sender] = Attestation({
            score: score,
            band: band,
            timestamp: uint64(block.timestamp),
            exists: true
        });

        unchecked {
            ++total;
            ++attestationCount[msg.sender];
        }

        emit VerdictAttested(txHash, msg.sender, score, band, uint64(block.timestamp));
    }

    /// @notice Read back what `attester` said about `txHash`.
    /// @return found Whether that attester has published a verdict at all.
    ///         Check this before trusting `score` -- a never-attested
    ///         transaction reads as score 0 / SAFE otherwise, which is
    ///         exactly the false negative this tool exists to prevent.
    function verdictOf(bytes32 txHash, address attester)
        external
        view
        returns (bool found, uint8 score, Band band, uint64 timestamp)
    {
        Attestation storage a = _attestations[txHash][attester];
        return (a.exists, a.score, a.band, a.timestamp);
    }
}
