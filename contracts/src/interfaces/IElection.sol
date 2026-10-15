// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IKeyperSet} from "./IKeyperSet.sol";
import {VotingTypes} from "../VotingTypes.sol";

interface IElection is IAccessControl {
    event DKGVoteRegistered(address indexed keyper, bytes pkElection);
    event DKGResultPublished(bytes pkElection, bytes[] committeePKs);
    /// @notice `zkProof` is the ballot's full proof; storage keeps only its keccak256.
    event VoteSubmitted(bytes32 indexed pseudonym, uint256 indexed ballotIndex, bytes zkProof);
    event AggregateVoteRegistered(address indexed keyper, bytes32 resultDigest);
    /// @notice Emitted once, when the aggregate reaches the keyper quorum. `tally` is
    ///         `abi.encode(EncryptedTally)`; storage keeps only `digest`, the hash the keypers
    ///         signed, so readers check the event against `aggregateDigest()`.
    event AggregatePublished(uint256 indexed electionId, bytes32 digest, bytes tally);
    event DecryptionSharePosted(uint8 indexed keyperIndex);
    event ResultPublished(uint256[] tally, uint8[] keyperIndices);
    event TallyStalledSet(bool stalled);
    event FeesWithdrawn(address indexed recipient, uint256 amount);
    event ElectionCancelled(uint256 indexed electionId);

    function VOTE_PROXY_ROLE() external view returns (bytes32);
    function RESULT_PUBLISHER_ROLE() external view returns (bytes32);

    function electionId() external view returns (uint256);
    function keyperSet() external view returns (IKeyperSet);
    function votingStart() external view returns (uint64);
    function votingEnd() external view returns (uint64);
    function selfSubmitFee() external view returns (uint256);
    function numCandidates() external view returns (uint32);
    function budget() external view returns (uint32);

    function cancelElection() external;
    function isCancelled() external view returns (bool);

    // forge-lint: disable-next-line(mixed-case-function)
    function voteDKGResult(bytes calldata pkElection, bytes[] calldata committeePKs) external;
    // forge-lint: disable-next-line(mixed-case-function)
    function voteDKGResultSigned(bytes calldata pkElection, bytes[] calldata committeePKs, bytes calldata keyperSig)
        external;
    // forge-lint: disable-next-line(mixed-case-function)
    function isDKGFinalized() external view returns (bool);

    function submitVote(VotingTypes.Ballot calldata ballot) external payable;
    function getNumBallots() external view returns (uint256);
    function getBallot(bytes32 pseudonym) external view returns (VotingTypes.BallotRecord memory record);
    function getBallots(uint256 startIndex, uint256 count)
        external
        view
        returns (VotingTypes.BallotRecord[] memory records);

    function submitAggregate(VotingTypes.EncryptedTally calldata aggregate) external;
    function submitAggregateSigned(VotingTypes.EncryptedTally calldata aggregate, bytes calldata keyperSig) external;
    /// @notice The canonical aggregate's digest, or zero until the quorum is reached.
    function aggregateDigest() external view returns (bytes32);
    /// @notice Block this election was created in: where readers start their log queries.
    function deployBlock() external view returns (uint256);

    function submitDecryptionShare(bytes[] calldata shares, VotingTypes.DLEQProof[] calldata proofs) external;
    function submitDecryptionShareSigned(
        bytes[] calldata shares, VotingTypes.DLEQProof[] calldata proofs, bytes calldata keyperSig
    ) external;
    function getDecryptionShares() external view returns (VotingTypes.DecryptionShare[] memory shares);

    function publishResult(uint256[] calldata totals, uint8[] calldata keyperIndices) external;
    function isResultFinalized() external view returns (bool);
    function getResult() external view returns (VotingTypes.ElectionResult memory result);
    function getPhase() external view returns (uint8 phase);
    function getElection()
        external
        view
        returns (VotingTypes.ElectionConfigView memory config, VotingTypes.DKGResult memory dkgResult);
    function withdrawFees(address payable recipient) external returns (uint256 amount);
}
