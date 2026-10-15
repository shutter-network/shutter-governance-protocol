// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Election} from "../src/Election.sol";
import {ElectionBase} from "../src/election/ElectionBase.sol";
import {IElection} from "../src/interfaces/IElection.sol";
import {KeyperSet} from "../src/KeyperSet.sol";
import {VotingTypes} from "../src/VotingTypes.sol";

contract ElectionTallyTest is Test {
    Election private election;
    KeyperSet private keyperSet;

    address private owner = address(0xA11CE);
    address private voter = address(0xCA57);
    address private voteProxy = address(0x970);
    address private resultPublisher = address(0xA66);
    address private keyper1 = address(0x1001);
    address private keyper2 = address(0x1002);
    address private keyper3 = address(0x1003);
    address private outsider = address(0xBAD);

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
        _submitVote();
    }

    function test_submitDecryptionShareStoresSharesAfterVotingEnds() external {
        bytes[] memory shares = _shares(40);
        VotingTypes.DLEQProof[] memory proofs = _proofs(11);

        _publishAggregate();  // decryption shares require a canonical aggregate
        vm.expectEmit(true, false, false, true, address(election));
        emit IElection.DecryptionSharePosted(0);

        vm.prank(keyper1);
        election.submitDecryptionShare(shares, proofs);

        VotingTypes.DecryptionShare[] memory allShares = election.getDecryptionShares();
        assertEq(allShares.length, 1);

        VotingTypes.DecryptionShare memory storedShare = allShares[0];
        assertEq(storedShare.keyperIndex, 0);
        assertEq(storedShare.submittedAt, votingEnd);
        assertEq(storedShare.shares.length, 3);
        assertEq(storedShare.shares[0], shares[0]);
        assertEq(storedShare.proofs[0].e, proofs[0].e);
        assertEq(storedShare.proofs[2].z, proofs[2].z);
    }

    function test_submitAggregateBecomesCanonicalAtQuorum() external {
        assertEq(election.getPhase(), 3);

        vm.warp(votingEnd);
        assertEq(election.getPhase(), 4);

        VotingTypes.EncryptedTally memory aggregate = _aggregate(70);

        // First keyper submits — not canonical yet (quorum is t+1 = 2).
        vm.prank(keyper1);
        election.submitAggregate(aggregate);
        assertEq(election.aggregateDigest(), bytes32(0));

        // Second keyper submits the byte-identical aggregate → canonical. Storage keeps the
        // digest; the full artifact is in the event.
        vm.expectEmit(true, false, false, true, address(election));
        emit IElection.AggregatePublished(1, _digest(aggregate), abi.encode(aggregate));
        vm.prank(keyper2);
        election.submitAggregate(aggregate);

        assertEq(election.aggregateDigest(), _digest(aggregate));
    }

    function test_submitAggregateDivergentSubmissionsDoNotFinalize() external {
        vm.warp(votingEnd);

        vm.prank(keyper1);
        election.submitAggregate(_aggregate(70));
        // A different aggregate from another keyper is a distinct vote — no quorum.
        vm.prank(keyper2);
        election.submitAggregate(_aggregate(71));

        assertEq(election.aggregateDigest(), bytes32(0));

        // The third keyper agreeing with keyper1 reaches quorum on that artifact.
        vm.prank(keyper3);
        election.submitAggregate(_aggregate(70));
        assertEq(election.aggregateDigest(), _digest(_aggregate(70)));
    }

    function test_submitAggregateRejectsUnauthorizedTimingAndBadPayload() external {
        // Before votingEnd: rejected.
        vm.warp(votingEnd - 1);
        vm.prank(keyper1);
        vm.expectRevert(abi.encodeWithSelector(ElectionBase.VotingStillOpen.selector, votingEnd - 1));
        election.submitAggregate(_aggregate(70));

        vm.warp(votingEnd);

        // Non-keyper: rejected.
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(ElectionBase.UnauthorizedKeyper.selector, outsider));
        election.submitAggregate(_aggregate(70));

        // Wrong candidate count: rejected.
        VotingTypes.EncryptedTally memory bad;
        bad.aggregates = new VotingTypes.Ciphertext[](2);
        bad.aggregates[0] = VotingTypes.Ciphertext({c1: _g2Point(1), c2: _g2Point(2)});
        bad.aggregates[1] = VotingTypes.Ciphertext({c1: _g2Point(3), c2: _g2Point(4)});
        vm.prank(keyper2);
        vm.expectRevert(ElectionBase.InvalidAggregatePayload.selector);
        election.submitAggregate(bad);
    }

    function test_submitAggregateOverrideUntilFinalizedThenFrozen() external {
        vm.warp(votingEnd);

        // keyper1 + keyper2 disagree → no quorum (t+1 = 2).
        vm.prank(keyper1);
        election.submitAggregate(_aggregate(70));
        vm.prank(keyper2);
        election.submitAggregate(_aggregate(71));
        assertEq(election.aggregateDigest(), bytes32(0));

        // keyper2 realizes it was wrong and OVERRIDES to keyper1's aggregate → quorum.
        vm.expectEmit(true, false, false, true, address(election));
        emit IElection.AggregatePublished(1, _digest(_aggregate(70)), abi.encode(_aggregate(70)));
        vm.prank(keyper2);
        election.submitAggregate(_aggregate(70));
        assertEq(election.aggregateDigest(), _digest(_aggregate(70)));

        // Once finalized, further submissions (even overrides) are frozen out.
        vm.prank(keyper3);
        vm.expectRevert(ElectionBase.AlreadyFinalized.selector);
        election.submitAggregate(_aggregate(70));
    }

    function test_getDecryptionSharesReturnsRanges() external {
        _publishAggregate();  // decryption shares require a canonical aggregate

        vm.prank(keyper1);
        election.submitDecryptionShare(_shares(40), _proofs(11));

        vm.prank(keyper2);
        election.submitDecryptionShare(_shares(50), _proofs(21));

        VotingTypes.DecryptionShare[] memory shares = election.getDecryptionShares();
        assertEq(shares.length, 2);
        assertEq(shares[0].keyperIndex, 0);
        assertEq(shares[1].keyperIndex, 1);
        assertEq(shares[0].submittedAt, votingEnd);
        assertEq(shares[1].submittedAt, votingEnd);
        assertEq(shares[0].shares[0], _g2Point(40));
        assertEq(shares[1].shares[2], _g2Point(52));
        assertEq(shares[0].proofs[0].e, 11);
        assertEq(shares[1].proofs[2].z, 26);
    }

    function test_submitDecryptionShareRejectsInvalidCallersAndTiming() external {
        vm.warp(votingEnd - 1);
        vm.prank(keyper1);
        vm.expectRevert(abi.encodeWithSelector(ElectionBase.VotingStillOpen.selector, votingEnd - 1));
        election.submitDecryptionShare(_shares(40), _proofs(11));

        _publishAggregate();  // pass the aggregate-published gate so the authz check is reached
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(ElectionBase.UnauthorizedKeyper.selector, outsider));
        election.submitDecryptionShare(_shares(40), _proofs(11));
    }

    function test_submitDecryptionShareRejectsBeforeAggregatePublished() external {
        vm.warp(votingEnd);  // past votingEnd, but no canonical aggregate exists yet
        vm.prank(keyper1);
        vm.expectRevert(ElectionBase.AggregateNotPublished.selector);
        election.submitDecryptionShare(_shares(40), _proofs(11));
    }

    function test_submitDecryptionShareRejectsDuplicateAndBadPayload() external {
        _publishAggregate();  // decryption shares require a canonical aggregate

        vm.startPrank(keyper1);
        election.submitDecryptionShare(_shares(40), _proofs(11));

        vm.expectRevert(abi.encodeWithSelector(ElectionBase.AlreadyVoted.selector, keyper1));
        election.submitDecryptionShare(_shares(41), _proofs(21));
        vm.stopPrank();

        bytes[] memory shortShares = new bytes[](2);
        shortShares[0] = _g2Point(40);
        shortShares[1] = _g2Point(41);

        vm.prank(keyper2);
        vm.expectRevert(ElectionBase.InvalidDecryptionSharePayload.selector);
        election.submitDecryptionShare(shortShares, _proofs(11));

        bytes[] memory badShare = _shares(50);
        badShare[1] = new bytes(95);

        vm.prank(keyper2);
        vm.expectRevert(abi.encodeWithSelector(ElectionBase.InvalidG2PointLength.selector, 95));
        election.submitDecryptionShare(badShare, _proofs(21));
    }

    function test_finalizeResultStoresResult() external {
        uint256[] memory totals = _totals();
        uint8[] memory keyperIndices = _keyperIndices();

        _publishAggregate();  // so the later keyper1 decryption-share submit is accepted
        vm.expectEmit(false, false, false, true, address(election));
        emit IElection.ResultPublished(totals, keyperIndices);

        vm.prank(resultPublisher);
        election.publishResult(totals, keyperIndices);

        assertTrue(election.isResultFinalized());
        assertEq(election.getPhase(), 4);

        VotingTypes.ElectionResult memory storedResult = election.getResult();
        assertEq(storedResult.tally.length, 3);
        assertEq(storedResult.tally[0], totals[0]);
        assertEq(storedResult.tally[1], totals[1]);
        assertEq(storedResult.tally[2], totals[2]);
        assertEq(storedResult.keyperIndices.length, 2);
        assertEq(storedResult.keyperIndices[0], 0);
        assertEq(storedResult.keyperIndices[1], 2);

        vm.prank(voter);
        vm.expectRevert(abi.encodeWithSelector(ElectionBase.VotingClosed.selector, votingEnd));
        election.submitVote{value: selfSubmitFee}(_ballot(_pseudonym("pseudo-2"), 20));

        vm.prank(keyper1);
        election.submitDecryptionShare(_shares(40), _proofs(11));
        assertEq(election.getDecryptionShares().length, 1);
    }

    function test_finalizeResultRejectsUnauthorizedAndInvalidPayloads() external {
        vm.warp(votingEnd);

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, outsider, election.RESULT_PUBLISHER_ROLE()
            )
        );
        vm.prank(outsider);
        election.publishResult(_totals(), _keyperIndices());

        uint256[] memory shortTotals = new uint256[](2);
        shortTotals[0] = 1;
        shortTotals[1] = 2;

        vm.prank(resultPublisher);
        vm.expectRevert(ElectionBase.InvalidResultPayload.selector);
        election.publishResult(shortTotals, _keyperIndices());

        uint8[] memory noKeypers = new uint8[](0);
        vm.prank(resultPublisher);
        vm.expectRevert(ElectionBase.InvalidResultPayload.selector);
        election.publishResult(_totals(), noKeypers);
    }

    function test_finalizeResultRejectsBeforeVotingEndsAndAllowsRepublish() external {
        vm.warp(votingEnd - 1);
        vm.prank(resultPublisher);
        vm.expectRevert(abi.encodeWithSelector(ElectionBase.VotingStillOpen.selector, votingEnd - 1));
        election.publishResult(_totals(), _keyperIndices());

        vm.warp(votingEnd);
        vm.startPrank(resultPublisher);
        election.publishResult(_totals(), _keyperIndices());

        uint256[] memory updatedTotals = _totals();
        updatedTotals[0] = 42;
        election.publishResult(updatedTotals, _keyperIndices());
        vm.stopPrank();

        VotingTypes.ElectionResult memory storedResult = election.getResult();
        assertEq(storedResult.tally[0], 42);
    }

    function test_getResultReturnsEmptyResultBeforePublication() external view {
        VotingTypes.ElectionResult memory result = election.getResult();
        assertEq(result.tally.length, 0);
        assertEq(result.keyperIndices.length, 0);
    }

    function test_tallyStalledMarkedByPublisherClearedByAdmin() external {
        _publishAggregate();  // warps to votingEnd
        bytes32 pubRole = election.RESULT_PUBLISHER_ROLE();    // read before pranks (external calls)
        bytes32 adminRole = election.DEFAULT_ADMIN_ROLE();
        assertFalse(election.tallyStalled());

        // Only the result publisher can MARK (set true).
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, outsider, pubRole));
        election.markTallyStalled();
        vm.prank(resultPublisher);
        election.markTallyStalled();
        assertTrue(election.tallyStalled());

        // The publisher CANNOT clear (admin-only, one-directional).
        vm.prank(resultPublisher);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, resultPublisher, adminRole));
        election.clearTallyStalled();

        // The election admin clears it (the retry).
        vm.prank(owner);
        election.clearTallyStalled();
        assertFalse(election.tallyStalled());
    }

    function test_markTallyStalledRejectsBeforeVotingEnd() external {
        vm.warp(votingEnd - 1);
        vm.prank(resultPublisher);
        vm.expectRevert(abi.encodeWithSelector(ElectionBase.VotingStillOpen.selector, votingEnd - 1));
        election.markTallyStalled();
    }

    function _finalizeDkg() private {
        bytes memory pkElection = _g2Point(1);
        bytes[] memory committeePKs = _committeePKs(20);

        vm.prank(keyper1);
        election.voteDKGResult(pkElection, committeePKs);

        vm.prank(keyper2);
        election.voteDKGResult(pkElection, committeePKs);
    }

    function _submitVote() private {
        vm.deal(voter, 1 ether);
        vm.warp(votingStart);
        vm.prank(voter);
        election.submitVote{value: selfSubmitFee}(_ballot(_pseudonym("pseudo-1"), 10));
    }

    /// Warp to votingEnd and reach the t+1 quorum on a canonical aggregate (keyper1 +
    /// keyper2 submit a byte-identical artifact) — the precondition for decryption shares.
    function _publishAggregate() private {
        vm.warp(votingEnd);
        vm.prank(keyper1);
        election.submitAggregate(_aggregate(70));
        vm.prank(keyper2);
        election.submitAggregate(_aggregate(70));
    }

    function _totals() private pure returns (uint256[] memory totals) {
        totals = new uint256[](3);
        totals[0] = 3;
        totals[1] = 1;
        totals[2] = 0;
    }

    function _keyperIndices() private pure returns (uint8[] memory keyperIndices) {
        keyperIndices = new uint8[](2);
        keyperIndices[0] = 0;
        keyperIndices[1] = 2;
    }

    function _ballot(bytes32 pseudonym, uint8 seed) private pure returns (VotingTypes.Ballot memory ballot) {
        ballot.pseudonym = pseudonym;
        ballot.vk = _g1Point(seed);
        ballot.ciphertexts = _ciphertexts(seed);
        ballot.zkProof = abi.encodePacked(seed, seed + 1, seed + 2);
        ballot.voterSignature = abi.encodePacked(bytes32(uint256(seed + 100)));
        ballot.wrAttestation = abi.encodePacked(bytes32(uint256(seed + 200)));
    }

    /// @dev The digest keypers sign and the contract stores for the canonical aggregate.
    function _digest(VotingTypes.EncryptedTally memory aggregate) private view returns (bytes32) {
        return keccak256(
            abi.encodePacked("SHUTTER-GOVERNANCE-PROTOCOL-AGGREGATE-v1", election.electionId(), abi.encode(aggregate))
        );
    }

    function _aggregate(uint8 seed) private pure returns (VotingTypes.EncryptedTally memory aggregate) {
        aggregate.aggregates = _ciphertexts(seed);
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

    function _shares(uint8 seed) private pure returns (bytes[] memory shares) {
        shares = new bytes[](3);
        shares[0] = _g2Point(seed);
        shares[1] = _g2Point(seed + 1);
        shares[2] = _g2Point(seed + 2);
    }

    function _proofs(uint256 seed) private pure returns (VotingTypes.DLEQProof[] memory proofs) {
        proofs = new VotingTypes.DLEQProof[](3);
        proofs[0] = VotingTypes.DLEQProof({e: seed, z: seed + 1});
        proofs[1] = VotingTypes.DLEQProof({e: seed + 2, z: seed + 3});
        proofs[2] = VotingTypes.DLEQProof({e: seed + 4, z: seed + 5});
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
            pkWR: bytes(""),
            resultPublisher: resultPublisher,
            voteProxy: voteProxy
        });
    }
}
