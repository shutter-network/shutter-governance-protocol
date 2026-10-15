// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Election} from "../src/Election.sol";
import {ElectionBase} from "../src/election/ElectionBase.sol";
import {IElection} from "../src/interfaces/IElection.sol";
import {KeyperSet} from "../src/KeyperSet.sol";
import {VotingTypes} from "../src/VotingTypes.sol";

contract ElectionVoteTest is Test {
    bytes private constant PK_WR = hex"01020304";

    Election private election;
    KeyperSet private keyperSet;

    address private owner = address(0xA11CE);
    address private voter = address(0xCA57);
    address private voteProxy = address(0x970);
    address private resultPublisher = address(0xA66);
    address private keyper1 = address(0x1001);
    address private keyper2 = address(0x1002);
    address private keyper3 = address(0x1003);

    uint64 private votingStart = 100;
    uint64 private votingEnd = 200;
    uint256 private selfSubmitFee = 0.01 ether;

    function setUp() external {
        address[] memory members = new address[](3);
        members[0] = keyper1;
        members[1] = keyper2;
        members[2] = keyper3;

        keyperSet = new KeyperSet(members, new string[](members.length), 2);
        election = new Election(owner, 1, keyperSet, _params());

        _finalizeDkg();
        vm.deal(voter, 1 ether);
        vm.deal(voteProxy, 1 ether);
    }

    function test_submitVoteStoresBallotPayload() external {
        VotingTypes.Ballot memory ballot = _ballot(_pseudonym("pseudo-1"), 10);

        vm.warp(votingStart);
        vm.expectEmit(true, true, false, true, address(election));
        emit IElection.VoteSubmitted(ballot.pseudonym, 0, ballot.zkProof); // the full proof is in the event

        vm.prank(voter);
        election.submitVote{value: selfSubmitFee}(ballot);

        assertEq(election.getNumBallots(), 1);
        assertEq(address(election).balance, selfSubmitFee);

        VotingTypes.BallotRecord[] memory records = election.getBallots(0, 1);
        VotingTypes.BallotView memory storedBallot = records[0].ballot;
        assertEq(storedBallot.pseudonym, ballot.pseudonym);
        assertEq(storedBallot.vk, ballot.vk);
        assertEq(storedBallot.zkProofHash, keccak256(ballot.zkProof)); // storage keeps only the commitment
        assertEq(storedBallot.voterSignature, ballot.voterSignature);
        assertEq(storedBallot.wrAttestation, ballot.wrAttestation);
        assertEq(storedBallot.ciphertexts.length, 3);
        assertEq(storedBallot.ciphertexts[1].c1, ballot.ciphertexts[1].c1);
    }

    function test_submitVoteWaivesExtraFeeForVoteProxy() external {
        vm.warp(votingStart);

        vm.prank(voteProxy);
        election.submitVote(_ballot(_pseudonym("pseudo-1"), 10));

        assertEq(address(election).balance, 0);
        assertEq(election.getNumBallots(), 1);
    }

    function test_submitVoteAllowsRevotesAsNewBallots() external {
        vm.warp(votingStart);

        vm.startPrank(voter);
        election.submitVote{value: selfSubmitFee}(_ballot(_pseudonym("same-pseudonym"), 10));
        election.submitVote{value: selfSubmitFee}(_ballot(_pseudonym("same-pseudonym"), 20));
        vm.stopPrank();

        assertEq(election.getNumBallots(), 2);
        VotingTypes.BallotRecord[] memory records = election.getBallots(0, 2);
        bytes32 firstPseudonym = records[0].ballot.pseudonym;
        bytes32 secondPseudonym = records[1].ballot.pseudonym;
        assertEq(firstPseudonym, secondPseudonym);

        VotingTypes.BallotRecord memory latestRecord = election.getBallot(_pseudonym("same-pseudonym"));
        assertEq(latestRecord.ballot.vk, records[1].ballot.vk);
        assertEq(latestRecord.ballot.ciphertexts[0].c1, records[1].ballot.ciphertexts[0].c1);
    }

    function test_getBallotsAndCiphertextsReturnRanges() external {
        vm.warp(votingStart);

        vm.startPrank(voter);
        election.submitVote{value: selfSubmitFee}(_ballot(_pseudonym("pseudo-1"), 10));
        election.submitVote{value: selfSubmitFee}(_ballot(_pseudonym("pseudo-2"), 20));
        vm.stopPrank();

        VotingTypes.BallotRecord[] memory records = election.getBallots(0, 2);
        assertEq(records.length, 2);
        assertEq(records[0].ballot.pseudonym, _pseudonym("pseudo-1"));
        assertEq(records[1].ballot.pseudonym, _pseudonym("pseudo-2"));
        assertEq(records[0].ballot.vk.length, 48);
        assertEq(records[1].ballot.voterSignature.length, 32);

        assertEq(records[1].ballot.ciphertexts.length, 3);
        assertEq(records[1].ballot.ciphertexts[0].c1, _g2Point(20));
        assertEq(records[1].ballot.ciphertexts[2].c2, _g2Point(25));
    }

    function test_getBallotByPseudonymAndElectionView() external {
        VotingTypes.Ballot memory ballot = _ballot(_pseudonym("pseudo-1"), 10);

        vm.warp(votingStart);
        vm.prank(voter);
        election.submitVote{value: selfSubmitFee}(ballot);

        VotingTypes.BallotRecord memory latestRecord = election.getBallot(_pseudonym("pseudo-1"));
        assertEq(latestRecord.ballot.pseudonym, ballot.pseudonym);
        assertEq(latestRecord.ballot.vk, ballot.vk);
        assertEq(latestRecord.ballot.wrAttestation, ballot.wrAttestation);

        (VotingTypes.ElectionConfigView memory config, VotingTypes.DKGResult memory dkgResult) = election.getElection();
        assertEq(config.electionId, 1);
        assertEq(config.thresholdN, 3);
        assertEq(config.thresholdT, 2);
        assertEq(config.numCandidates, 3);
        assertEq(config.pkWR, PK_WR);
        assertEq(dkgResult.pkElection.length, 96);
        assertEq(dkgResult.committeePKs.length, 3);
    }

    function test_submitVoteRejectsWrongFee() external {
        vm.warp(votingStart);

        vm.prank(voter);
        vm.expectRevert(abi.encodeWithSelector(ElectionBase.InvalidVoteFee.selector, selfSubmitFee, 0));
        election.submitVote(_ballot(_pseudonym("pseudo-1"), 10));

        vm.prank(voteProxy);
        vm.expectRevert(abi.encodeWithSelector(ElectionBase.InvalidVoteFee.selector, 0, selfSubmitFee));
        election.submitVote{value: selfSubmitFee}(_ballot(_pseudonym("pseudo-1"), 10));
    }

    function test_submitVoteRejectsOutsideVotingWindow() external {
        vm.warp(votingStart - 1);

        vm.prank(voter);
        vm.expectRevert(abi.encodeWithSelector(ElectionBase.VotingNotStarted.selector, votingStart - 1));
        election.submitVote{value: selfSubmitFee}(_ballot(_pseudonym("pseudo-1"), 10));

        vm.warp(votingEnd);

        vm.prank(voter);
        vm.expectRevert(abi.encodeWithSelector(ElectionBase.VotingClosed.selector, votingEnd));
        election.submitVote{value: selfSubmitFee}(_ballot(_pseudonym("pseudo-1"), 10));
    }

    function test_submitVoteRejectsBeforeDKGFinalization() external {
        Election notReadyElection = new Election(owner, 2, keyperSet, _params());

        vm.warp(votingStart);
        vm.prank(voter);
        vm.expectRevert(ElectionBase.DKGNotFinalized.selector);
        notReadyElection.submitVote{value: selfSubmitFee}(_ballot(_pseudonym("pseudo-1"), 10));
    }

    function test_submitVoteRejectsInvalidPayload() external {
        vm.warp(votingStart);

        VotingTypes.Ballot memory missingProof = _ballot(_pseudonym("pseudo-1"), 10);
        missingProof.zkProof = bytes("");

        vm.prank(voter);
        vm.expectRevert(ElectionBase.InvalidVotePayload.selector);
        election.submitVote{value: selfSubmitFee}(missingProof);

        VotingTypes.Ballot memory badVk = _ballot(_pseudonym("pseudo-1"), 10);
        badVk.vk = new bytes(47);

        vm.prank(voter);
        vm.expectRevert(ElectionBase.InvalidVotePayload.selector);
        election.submitVote{value: selfSubmitFee}(badVk);

        VotingTypes.Ballot memory badCiphertexts = _ballot(_pseudonym("pseudo-1"), 10);
        badCiphertexts.ciphertexts = new VotingTypes.Ciphertext[](2);
        badCiphertexts.ciphertexts[0] = VotingTypes.Ciphertext({c1: _g2Point(10), c2: _g2Point(11)});
        badCiphertexts.ciphertexts[1] = VotingTypes.Ciphertext({c1: _g2Point(12), c2: _g2Point(13)});

        vm.prank(voter);
        vm.expectRevert(ElectionBase.InvalidVotePayload.selector);
        election.submitVote{value: selfSubmitFee}(badCiphertexts);

        VotingTypes.Ballot memory badPoint = _ballot(_pseudonym("pseudo-1"), 10);
        badPoint.ciphertexts[1].c1 = new bytes(95);

        vm.prank(voter);
        vm.expectRevert(abi.encodeWithSelector(ElectionBase.InvalidG2PointLength.selector, 95));
        election.submitVote{value: selfSubmitFee}(badPoint);

        vm.prank(voter);
        vm.expectRevert(ElectionBase.InvalidPseudonym.selector);
        election.submitVote{value: selfSubmitFee}(_ballot(bytes32(0), 10));
    }

    function _finalizeDkg() private {
        bytes memory pkElection = _g2Point(1);
        bytes[] memory committeePKs = _committeePKs(20);

        vm.prank(keyper1);
        election.voteDKGResult(pkElection, committeePKs);

        vm.prank(keyper2);
        election.voteDKGResult(pkElection, committeePKs);
    }

    function _ballot(bytes32 pseudonym, uint8 seed) private pure returns (VotingTypes.Ballot memory ballot) {
        ballot.pseudonym = pseudonym;
        ballot.vk = _g1Point(seed);
        ballot.ciphertexts = _ciphertexts(seed);
        ballot.zkProof = abi.encodePacked(seed, seed + 1, seed + 2);
        ballot.voterSignature = abi.encodePacked(bytes32(uint256(seed + 100)));
        ballot.wrAttestation = abi.encodePacked(bytes32(uint256(seed + 200)));
    }

    function _pseudonym(string memory label) private pure returns (bytes32) {
        return keccak256(bytes(label));
    }

    function _ciphertexts(uint8 seed) private pure returns (VotingTypes.Ciphertext[] memory ciphertexts) {
        ciphertexts = new VotingTypes.Ciphertext[](3);
        ciphertexts[0] = VotingTypes.Ciphertext({c1: _g2Point(seed), c2: _g2Point(seed + 1)});
        ciphertexts[1] = VotingTypes.Ciphertext({c1: _g2Point(seed + 2), c2: _g2Point(seed + 3)});
        ciphertexts[2] = VotingTypes.Ciphertext({c1: _g2Point(seed + 4), c2: _g2Point(seed + 5)});
    }

    function _committeePKs(uint8 seed) private pure returns (bytes[] memory committeePKs) {
        committeePKs = new bytes[](3);
        committeePKs[0] = _g2Point(seed);
        committeePKs[1] = _g2Point(seed + 1);
        committeePKs[2] = _g2Point(seed + 2);
    }

    function _g1Point(uint8 seed) private pure returns (bytes memory point) {
        point = new bytes(48);
        for (uint256 index = 0; index < point.length; index++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            point[index] = bytes1(seed + uint8(index));
        }
    }

    function _g2Point(uint8 seed) private pure returns (bytes memory point) {
        point = new bytes(96);
        for (uint256 index = 0; index < point.length; index++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            point[index] = bytes1(seed + uint8(index));
        }
    }

    function _params() private view returns (VotingTypes.ElectionParams memory) {
        return VotingTypes.ElectionParams({
            mode: 0, variant: 0, weighted: false, scale: 1, duplicatePolicy: 1, protocolVersion: "v1",
            votingStart: votingStart,
            votingEnd: votingEnd,
            selfSubmitFee: selfSubmitFee,
            numCandidates: 3,
            budget: 1,
            pkWR: PK_WR,
            resultPublisher: resultPublisher,
            voteProxy: voteProxy
        });
    }
}
