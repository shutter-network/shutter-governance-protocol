// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Election} from "../src/Election.sol";
import {ElectionBase} from "../src/election/ElectionBase.sol";
import {IElection} from "../src/interfaces/IElection.sol";
import {KeyperSet} from "../src/KeyperSet.sol";
import {VotingTypes} from "../src/VotingTypes.sol";

contract ElectionDKGTest is Test {
    Election private election;
    KeyperSet private keyperSet;

    address private owner = address(0xA11CE);
    address private keyper1 = address(0x1001);
    address private keyper2 = address(0x1002);
    address private keyper3 = address(0x1003);
    address private outsider = address(0xBAD);
    address private resultPublisher = address(0xA66);
    address private voteProxy = address(0x970);

    function setUp() external {
        address[] memory members = new address[](3);
        members[0] = keyper1;
        members[1] = keyper2;
        members[2] = keyper3;

        keyperSet = new KeyperSet(members, new string[](members.length), 2);
        election = new Election(owner, 1, keyperSet, _params());
    }

    function test_voteDKGResultFinalizesAtThreshold() external {
        bytes memory pkElection = _g2Point(1);
        bytes[] memory committeePKs = _committeePKs(10);

        vm.expectEmit(true, false, false, true, address(election));
        emit IElection.DKGVoteRegistered(keyper1, pkElection);

        vm.prank(keyper1);
        election.voteDKGResult(pkElection, committeePKs);

        assertFalse(election.isDKGFinalized());

        vm.expectEmit(false, false, false, true, address(election));
        emit IElection.DKGResultPublished(pkElection, committeePKs);

        vm.prank(keyper2);
        election.voteDKGResult(pkElection, committeePKs);

        assertTrue(election.isDKGFinalized());
        (, VotingTypes.DKGResult memory dkgResult) = election.getElection();
        assertEq(dkgResult.pkElection, pkElection);
        assertEq(dkgResult.committeePKs.length, 3);
        assertEq(dkgResult.committeePKs[0], committeePKs[0]);
        assertEq(dkgResult.committeePKs[1], committeePKs[1]);
        assertEq(dkgResult.committeePKs[2], committeePKs[2]);
    }

    function test_voteDKGResultRejectsNonMember() external {
        bytes memory pkElection = _g2Point(1);
        bytes[] memory committeePKs = _committeePKs(10);

        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(ElectionBase.UnauthorizedKeyper.selector, outsider));
        election.voteDKGResult(pkElection, committeePKs);
    }

    function test_voteDKGResultRejectsDuplicateVote() external {
        bytes memory pkElection = _g2Point(1);
        bytes[] memory committeePKs = _committeePKs(10);

        vm.startPrank(keyper1);
        election.voteDKGResult(pkElection, committeePKs);

        vm.expectRevert(abi.encodeWithSelector(ElectionBase.AlreadyVoted.selector, keyper1));
        election.voteDKGResult(_g2Point(2), _committeePKs(20));
        vm.stopPrank();
    }

    function test_voteDKGResultRejectsInvalidLengths() external {
        bytes memory shortPoint = new bytes(95);
        bytes memory pkElection = _g2Point(1);
        bytes[] memory committeePKs = _committeePKs(10);

        vm.prank(keyper1);
        vm.expectRevert(abi.encodeWithSelector(ElectionBase.InvalidG2PointLength.selector, 95));
        election.voteDKGResult(shortPoint, committeePKs);

        committeePKs[1] = shortPoint;

        vm.prank(keyper1);
        vm.expectRevert(abi.encodeWithSelector(ElectionBase.InvalidG2PointLength.selector, 95));
        election.voteDKGResult(pkElection, committeePKs);
    }

    function test_voteDKGResultRejectsWrongCommitteeLength() external {
        bytes[] memory committeePKs = new bytes[](2);
        committeePKs[0] = _g2Point(10);
        committeePKs[1] = _g2Point(11);

        vm.prank(keyper1);
        vm.expectRevert(abi.encodeWithSelector(ElectionBase.InvalidCommitteeLength.selector, 2, 3));
        election.voteDKGResult(_g2Point(1), committeePKs);
    }

    function test_voteDKGResultFinalizesResultThatReachesThreshold() external {
        bytes memory maliciousPkElection = _g2Point(1);
        bytes[] memory maliciousCommitteePKs = _committeePKs(10);

        bytes memory honestPkElection = _g2Point(2);
        bytes[] memory honestCommitteePKs = _committeePKs(20);

        vm.prank(keyper1);
        election.voteDKGResult(maliciousPkElection, maliciousCommitteePKs);
        assertFalse(election.isDKGFinalized());

        (, VotingTypes.DKGResult memory emptyDkgResult) = election.getElection();
        assertEq(emptyDkgResult.pkElection.length, 0);
        assertEq(emptyDkgResult.committeePKs.length, 0);

        vm.prank(keyper2);
        election.voteDKGResult(honestPkElection, honestCommitteePKs);
        assertFalse(election.isDKGFinalized());

        vm.prank(keyper3);
        election.voteDKGResult(honestPkElection, honestCommitteePKs);

        assertTrue(election.isDKGFinalized());
        (, VotingTypes.DKGResult memory dkgResult) = election.getElection();
        assertEq(dkgResult.pkElection, honestPkElection);
        assertEq(dkgResult.committeePKs.length, 3);
        assertEq(dkgResult.committeePKs[0], honestCommitteePKs[0]);
        assertEq(dkgResult.committeePKs[1], honestCommitteePKs[1]);
        assertEq(dkgResult.committeePKs[2], honestCommitteePKs[2]);
    }

    function test_voteDKGResultRequiresSameCommitteeKeyOrdering() external {
        bytes memory pkElection = _g2Point(1);
        bytes[] memory jumbledCommitteePKs = _committeePKs(10);
        bytes[] memory canonicalCommitteePKs = _committeePKs(10);

        jumbledCommitteePKs[0] = canonicalCommitteePKs[2];
        jumbledCommitteePKs[1] = canonicalCommitteePKs[0];
        jumbledCommitteePKs[2] = canonicalCommitteePKs[1];

        vm.prank(keyper1);
        election.voteDKGResult(pkElection, jumbledCommitteePKs);
        assertFalse(election.isDKGFinalized());

        vm.prank(keyper2);
        election.voteDKGResult(pkElection, canonicalCommitteePKs);
        assertFalse(election.isDKGFinalized());

        vm.prank(keyper3);
        election.voteDKGResult(pkElection, canonicalCommitteePKs);

        assertTrue(election.isDKGFinalized());
        (, VotingTypes.DKGResult memory dkgResult) = election.getElection();
        assertEq(dkgResult.pkElection, pkElection);
        assertEq(dkgResult.committeePKs.length, 3);
        assertEq(dkgResult.committeePKs[0], canonicalCommitteePKs[0]);
        assertEq(dkgResult.committeePKs[1], canonicalCommitteePKs[1]);
        assertEq(dkgResult.committeePKs[2], canonicalCommitteePKs[2]);
    }

    function test_voteDKGResultRejectsAfterFinalization() external {
        bytes memory pkElection = _g2Point(1);
        bytes[] memory committeePKs = _committeePKs(10);

        vm.prank(keyper1);
        election.voteDKGResult(pkElection, committeePKs);

        vm.prank(keyper2);
        election.voteDKGResult(pkElection, committeePKs);

        vm.prank(keyper3);
        vm.expectRevert(ElectionBase.AlreadyFinalized.selector);
        election.voteDKGResult(pkElection, committeePKs);
    }

    function _committeePKs(uint8 seed) private pure returns (bytes[] memory committeePKs) {
        committeePKs = new bytes[](3);
        committeePKs[0] = _g2Point(seed);
        committeePKs[1] = _g2Point(seed + 1);
        committeePKs[2] = _g2Point(seed + 2);
    }

    function _g2Point(uint8 seed) private pure returns (bytes memory point) {
        point = new bytes(96);
        for (uint256 index = 0; index < point.length; index++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            point[index] = bytes1(seed + uint8(index));
        }
    }

    // -- DKG closes when voting opens ------------------------------------------- //

    /// A vote at or after votingStart used to be accepted, so a late vote could finalize
    /// the key of an election that had already failed for lack of one.
    function test_voteDKGResultRejectedOnceVotingStarted() external {
        vm.prank(keyper1);
        election.voteDKGResult(_g2Point(1), _committeePKs(10));

        vm.warp(100); // votingStart
        vm.prank(keyper2);
        vm.expectRevert(abi.encodeWithSelector(ElectionBase.DKGClosed.selector, 100));
        election.voteDKGResult(_g2Point(1), _committeePKs(10));
        assertFalse(election.isDKGFinalized());
    }

    // -- config checks ------------------------------------------------------------ //

    function test_constructorRejectsUnknownEnumValues() external {
        VotingTypes.ElectionParams memory p = _params();
        p.mode = 2;
        vm.expectRevert(ElectionBase.InvalidConfig.selector);
        new Election(owner, 2, keyperSet, p);

        p = _params();
        p.variant = 2;
        vm.expectRevert(ElectionBase.InvalidConfig.selector);
        new Election(owner, 2, keyperSet, p);

        p = _params();
        p.duplicatePolicy = 2;
        vm.expectRevert(ElectionBase.InvalidConfig.selector);
        new Election(owner, 2, keyperSet, p);
    }

    function test_weiScaleIsStored() external {
        VotingTypes.ElectionParams memory p = _params();
        p.weighted = true;
        p.scale = 1e15; // wei-denominated token weights; does not fit uint32
        Election e = new Election(owner, 2, keyperSet, p);
        assertEq(e.scale(), 1e15);
        (VotingTypes.ElectionConfigView memory cfg,) = e.getElection();
        assertEq(cfg.scale, 1e15);
    }

    function test_deployBlockIsRecorded() external {
        vm.roll(1234);
        Election later = new Election(owner, 2, keyperSet, _params());
        assertEq(later.deployBlock(), 1234);
    }

    function _params() private view returns (VotingTypes.ElectionParams memory) {
        return VotingTypes.ElectionParams({
            mode: 0, variant: 0, weighted: false, scale: 1, duplicatePolicy: 1, protocolVersion: "v1",
            votingStart: 100,
            votingEnd: 200,
            selfSubmitFee: 0.01 ether,
            numCandidates: 3,
            budget: 1,
            pkWR: bytes(""),
            resultPublisher: resultPublisher,
            voteProxy: voteProxy
        });
    }
}
