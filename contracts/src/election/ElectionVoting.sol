// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

import {ElectionBase} from "./ElectionBase.sol";
import {VotingTypes} from "../VotingTypes.sol";

abstract contract ElectionVoting is ElectionBase {
    function submitVote(VotingTypes.Ballot calldata ballot) external payable {
        _requireNotCancelled();
        if (!dkgFinalized) revert DKGNotFinalized();
        if (block.timestamp < votingStart) revert VotingNotStarted(block.timestamp);
        if (block.timestamp >= votingEnd) revert VotingClosed(block.timestamp);
        if (ballot.pseudonym == bytes32(0)) revert InvalidPseudonym();
        if (
            ballot.vk.length != 48 || ballot.zkProof.length == 0 || ballot.voterSignature.length == 0
                || ballot.wrAttestation.length == 0 || ballot.ciphertexts.length != numCandidates
        ) {
            revert InvalidVotePayload();
        }

        uint256 expectedFee = hasRole(VOTE_PROXY_ROLE, msg.sender) ? 0 : selfSubmitFee;
        if (msg.value != expectedFee) revert InvalidVoteFee(expectedFee, msg.value);

        for (uint256 index = 0; index < ballot.ciphertexts.length; index++) {
            _requireG2Point(ballot.ciphertexts[index].c1);
            _requireG2Point(ballot.ciphertexts[index].c2);
        }

        ballotRecords.push();
        uint256 ballotIndex = ballotRecords.length - 1;
        VotingTypes.BallotRecord storage record = ballotRecords[ballotIndex];
        record.ballot.pseudonym = ballot.pseudonym;
        record.ballot.vk = ballot.vk;
        record.ballot.zkProofHash = keccak256(ballot.zkProof); // the proof itself is in the event
        record.ballot.voterSignature = ballot.voterSignature;
        record.ballot.wrAttestation = ballot.wrAttestation;
        record.submittedAt = uint64(block.timestamp);
        record.submittedBy = msg.sender;

        for (uint256 index = 0; index < ballot.ciphertexts.length; index++) {
            record.ballot.ciphertexts.push(ballot.ciphertexts[index]);
        }

        ballotIndexPlusOneByPseudonym[ballot.pseudonym] = ballotIndex + 1;

        emit VoteSubmitted(ballot.pseudonym, ballotIndex, ballot.zkProof);
    }

    function getNumBallots() external view returns (uint256) {
        return ballotRecords.length;
    }

    function getBallot(bytes32 pseudonym) external view returns (VotingTypes.BallotRecord memory record) {
        uint256 ballotIndexPlusOne = ballotIndexPlusOneByPseudonym[pseudonym];
        if (ballotIndexPlusOne == 0) revert BallotNotFound(pseudonym);
        return ballotRecords[ballotIndexPlusOne - 1];
    }

    function getBallots(uint256 startIndex, uint256 count) external view returns (VotingTypes.BallotRecord[] memory records)
    {
        records = new VotingTypes.BallotRecord[](count);
        for (uint256 index = 0; index < count; index++) {
            records[index] = ballotRecords[startIndex + index];
        }
    }
}
