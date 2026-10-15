// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ElectionBase} from "./ElectionBase.sol";
import {VotingTypes} from "../VotingTypes.sol";

abstract contract ElectionTally is ElectionBase {
    /// @notice Aggregate submission authorized by ``msg.sender`` (keyper sends its own tx).
    /// @dev The committee owns aggregation: each keyper re-derives the deterministic
    ///      aggregate from the ordered ballots and submits it. The aggregate becomes
    ///      canonical only once ``t + 1`` keypers submit a **byte-identical** artifact
    ///      (mirroring the DKG-result quorum) — no single writer asserts it.
    function submitAggregate(VotingTypes.EncryptedTally calldata aggregate) external {
        _registerAggregate(msg.sender, _aggregateDigest(aggregate), aggregate);
    }

    /// @notice Aggregate submission authorized by an embedded keyper signature (meta-tx).
    /// @dev A relayer submits and pays gas; the vote is attributed to the
    ///      ``ecrecover``ed keyper. The signature is an EIP-191 personal-sign over
    ///      ``keccak256("SHUTTER-GOVERNANCE-PROTOCOL-AGGREGATE-v1" ‖ electionId ‖ abi.encode(aggregate))``.
    function submitAggregateSigned(VotingTypes.EncryptedTally calldata aggregate, bytes calldata keyperSig) external {
        bytes32 digest = _aggregateDigest(aggregate);
        address signer = ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(digest), keyperSig);
        _registerAggregate(signer, digest, aggregate);
    }

    /// @dev Digest that both (a) the keyper signs and (b) groups byte-identical
    ///      submissions for the quorum count. Byte-identical for honest keypers.
    function _aggregateDigest(VotingTypes.EncryptedTally calldata aggregate) private view returns (bytes32) {
        return
            keccak256(abi.encodePacked("SHUTTER-GOVERNANCE-PROTOCOL-AGGREGATE-v1", electionId, abi.encode(aggregate)));
    }

    function _registerAggregate(address voter, bytes32 resultDigest, VotingTypes.EncryptedTally calldata aggregate)
        private
    {
        _requireNotCancelled();
        if (!dkgFinalized) revert DKGNotFinalized();
        if (block.timestamp < votingEnd) revert VotingStillOpen(block.timestamp);
        if (aggregatePublished) revert AlreadyFinalized(); // finalized → frozen
        if (!keyperSet.isMember(voter)) revert UnauthorizedKeyper(voter);
        if (aggregate.aggregates.length != numCandidates) revert InvalidAggregatePayload();

        // Mutable until finalized: a keyper may override its earlier aggregate so honest
        // keypers can re-converge (deterministic re-derivation, unlike append-only DKG).
        bytes32 prev = aggregateVoteDigestOf[voter];
        if (prev == resultDigest) return; // idempotent resend of this keyper's current vote
        if (prev != bytes32(0)) {
            aggregateVoteCountByResult[prev] -= 1; // move the vote off the old digest
        }
        aggregateVoteDigestOf[voter] = resultDigest;
        aggregateVoteCountByResult[resultDigest] += 1;
        emit AggregateVoteRegistered(voter, resultDigest);

        if (aggregateVoteCountByResult[resultDigest] >= keyperSet.getThreshold()) {
            // Keep only the digest the keypers signed; publish the artifact (sums, admitted
            // set, exclusions, weight totals) in the event for readers to check against it.
            aggregateDigest = resultDigest;
            aggregatePublished = true;
            emit AggregatePublished(electionId, resultDigest, abi.encode(aggregate));
        }
    }

    function publishResult(uint256[] calldata totals, uint8[] calldata keyperIndices)
        external
        onlyRole(RESULT_PUBLISHER_ROLE)
    {
        _requireNotCancelled();
        if (!dkgFinalized) revert DKGNotFinalized();
        if (block.timestamp < votingEnd) revert VotingStillOpen(block.timestamp);
        if (totals.length != numCandidates || keyperIndices.length == 0) revert InvalidResultPayload();

        resultFinalized = true;
        electionResult.tally = totals;
        electionResult.keyperIndices = keyperIndices;

        emit ResultPublished(totals, keyperIndices);
    }

    function getResult() external view returns (VotingTypes.ElectionResult memory result) {
        return electionResult;
    }

    /// @notice The result publisher (the off-chain coordinator) marks the tally stalled
    ///         after exhausting its attempts. One-directional — only ever sets `true`; the
    ///         coordinator is the sole party that can stall. Not a protocol gate: a published
    ///         result wins. Surfaced to the dashboard via the `tallyStalled` getter.
    function markTallyStalled() external onlyRole(RESULT_PUBLISHER_ROLE) {
        _requireNotCancelled();
        if (block.timestamp < votingEnd) revert VotingStillOpen(block.timestamp);
        if (resultFinalized) revert AlreadyFinalized(); // result wins; nothing to stall
        tallyStalled = true;
        emit TallyStalledSet(true);
    }

    /// @notice The election admin clears a stall (the "retry" action) so the coordinator
    ///         resumes driving with a fresh attempt budget. Admin-only and one-directional —
    ///         it can only clear, never set. A restart alone never resurrects a stall; this
    ///         is the sole way out (besides a published result → Complete).
    function clearTallyStalled() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _requireNotCancelled();
        tallyStalled = false;
        emit TallyStalledSet(false);
    }
}
