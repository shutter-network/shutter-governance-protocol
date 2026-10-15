// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ElectionBase} from "./ElectionBase.sol";

abstract contract ElectionDKG is ElectionBase {
    /// @notice DKG result vote authorized by ``msg.sender`` (keyper sends its own tx).
    // forge-lint: disable-next-line(mixed-case-function)
    function voteDKGResult(bytes calldata pkElection, bytes[] calldata committeePKs) external {
        _requireNotCancelled();
        if (dkgFinalized) revert AlreadyFinalized();
        _registerDKGVote(msg.sender, pkElection, committeePKs);
    }

    /// @notice DKG result vote authorized by an embedded keyper signature (meta-tx).
    /// @dev A relayer (the data-layer service) submits and pays gas; the vote is
    ///      attributed on-chain to the ``ecrecover``ed keyper, not the tx sender —
    ///      so keypers never touch the chain yet authorship is theirs and
    ///      unforgeable. The signature is an EIP-191 personal-sign over
    ///      ``keccak256("SHUTTER-GOVERNANCE-PROTOCOL-DKG-RESULT-v1" ‖ electionId ‖ pkElection ‖ abi.encode(committeePKs))``.
    // forge-lint: disable-next-line(mixed-case-function)
    function voteDKGResultSigned(bytes calldata pkElection, bytes[] calldata committeePKs, bytes calldata keyperSig)
        external
    {
        _requireNotCancelled();
        if (dkgFinalized) revert AlreadyFinalized();
        bytes32 digest = keccak256(
            abi.encodePacked(
                "SHUTTER-GOVERNANCE-PROTOCOL-DKG-RESULT-v1", electionId, pkElection, abi.encode(committeePKs)
            )
        );
        address signer = ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(digest), keyperSig);
        _registerDKGVote(signer, pkElection, committeePKs);
    }

    function _registerDKGVote(address voter, bytes calldata pkElection, bytes[] calldata committeePKs) private {
        if (block.timestamp >= votingStart) revert DKGClosed(block.timestamp);
        if (!keyperSet.isMember(voter)) revert UnauthorizedKeyper(voter);
        if (hasVotedForDKG[voter]) revert AlreadyVoted(voter);

        _requireG2Point(pkElection);
        uint64 numMembers = keyperSet.getNumMembers();
        if (committeePKs.length != numMembers) revert InvalidCommitteeLength(committeePKs.length, numMembers);
        for (uint256 index = 0; index < committeePKs.length; index++) {
            _requireG2Point(committeePKs[index]);
        }

        bytes32 resultDigest = keccak256(abi.encode(pkElection, committeePKs));
        hasVotedForDKG[voter] = true;
        dkgVoteCountByResult[resultDigest] += 1;

        emit DKGVoteRegistered(voter, pkElection);

        if (dkgVoteCountByResult[resultDigest] >= keyperSet.getThreshold()) {
            electionPublicKey = pkElection;
            _storeCommitteePublicKeys(committeePKs);
            dkgFinalized = true;
            emit DKGResultPublished(electionPublicKey, committeePublicKeys);
        }
    }

    function _storeCommitteePublicKeys(bytes[] calldata committeePKs) private {
        delete committeePublicKeys;
        for (uint256 index = 0; index < committeePKs.length; index++) {
            committeePublicKeys.push(committeePKs[index]);
        }
    }
}
