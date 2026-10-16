// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Election} from "../src/Election.sol";
import {ElectionBase} from "../src/election/ElectionBase.sol";
import {IElection} from "../src/interfaces/IElection.sol";
import {KeyperSet} from "../src/KeyperSet.sol";
import {VotingTypes} from "../src/VotingTypes.sol";

/// @notice Meta-tx (ecrecover) writes: a relayer pays gas, on-chain authorship is
///         the keyper that signed the payload — keypers never send a tx themselves.
contract ElectionMetaTxTest is Test {
    Election private election;
    KeyperSet private keyperSet;

    address private owner = address(0xA11CE);
    address private resultPublisher = address(0xA66);
    address private voteProxy = address(0x970);
    address private relayer = address(0xBEEF); // pays gas, is NOT a keyper

    uint256 private constant K1_PK = 0x1111111111111111111111111111111111111111111111111111111111111111;
    uint256 private constant K2_PK = 0x2222222222222222222222222222222222222222222222222222222222222222;
    uint256 private constant OUTSIDER_PK = 0x4444444444444444444444444444444444444444444444444444444444444444;

    uint64 private votingStart = 1000;
    uint64 private votingEnd = 2000;

    function setUp() external {
        address[] memory members = new address[](3);
        members[0] = vm.addr(K1_PK);
        members[1] = vm.addr(K2_PK);
        members[2] = address(0x1003);
        keyperSet = new KeyperSet(members, new string[](members.length), 2);
        election = new Election(owner, 1, keyperSet, _params());
    }

    function test_voteDKGResultSigned_attributesToKeyperNotRelayer() external {
        bytes memory pk = _g2Point(1);
        bytes[] memory committee = _committee(10);
        bytes memory sig1 = _signDkg(K1_PK, pk, committee);

        vm.expectEmit(true, false, false, true, address(election));
        emit IElection.DKGVoteRegistered(vm.addr(K1_PK), pk);
        vm.prank(relayer); // relayer sends the tx + pays gas
        election.voteDKGResultSigned(pk, committee, sig1);
        assertFalse(election.isDKGFinalized()); // 1 of 2

        vm.prank(relayer);
        election.voteDKGResultSigned(pk, committee, _signDkg(K2_PK, pk, committee));
        assertTrue(election.isDKGFinalized());
        (, VotingTypes.DKGResult memory dkg) = election.getElection();
        assertEq(dkg.pkElection, pk);
    }

    function test_voteDKGResultSigned_rejectsNonKeyperSignature() external {
        bytes memory pk = _g2Point(1);
        bytes[] memory committee = _committee(10);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(ElectionBase.UnauthorizedKeyper.selector, vm.addr(OUTSIDER_PK)));
        election.voteDKGResultSigned(pk, committee, _signDkg(OUTSIDER_PK, pk, committee));
    }

    function test_submitDecryptionShareSigned_attributesToKeyper() external {
        // Finalize DKG (signed) first.
        bytes memory pk = _g2Point(1);
        bytes[] memory committee = _committee(10);
        vm.startPrank(relayer);
        election.voteDKGResultSigned(pk, committee, _signDkg(K1_PK, pk, committee));
        election.voteDKGResultSigned(pk, committee, _signDkg(K2_PK, pk, committee));
        vm.stopPrank();

        vm.warp(votingEnd);
        // Publish a canonical aggregate (signed, t+1 quorum) — the precondition for shares.
        VotingTypes.EncryptedTally memory agg;
        agg.aggregates = _ciphertexts(70);
        vm.startPrank(relayer);
        election.submitAggregateSigned(agg, _signAggregate(K1_PK, agg));
        election.submitAggregateSigned(agg, _signAggregate(K2_PK, agg));
        vm.stopPrank();

        bytes[] memory shares = _shares(40);
        VotingTypes.DLEQProof[] memory proofs = _proofs(11);
        bytes memory sig = _signShare(K1_PK, shares, proofs);

        vm.prank(relayer);
        election.submitDecryptionShareSigned(shares, proofs, sig);

        VotingTypes.DecryptionShare[] memory all = election.getDecryptionShares();
        assertEq(all.length, 1);
        assertEq(all[0].keyperIndex, 0); // keyper 1 is member index 0
    }

    function test_submitAggregateSigned_becomesCanonicalAtQuorum() external {
        // Finalize DKG (signed) first.
        bytes memory pk = _g2Point(1);
        bytes[] memory committee = _committee(10);
        vm.startPrank(relayer);
        election.voteDKGResultSigned(pk, committee, _signDkg(K1_PK, pk, committee));
        election.voteDKGResultSigned(pk, committee, _signDkg(K2_PK, pk, committee));
        vm.stopPrank();

        vm.warp(votingEnd);
        VotingTypes.EncryptedTally memory agg;
        agg.aggregates = _ciphertexts(70);

        // Relayer submits keyper1's signed aggregate — attributed to keyper1, not relayer.
        vm.expectEmit(true, false, false, false, address(election));
        emit IElection.AggregateVoteRegistered(vm.addr(K1_PK), bytes32(0));
        vm.prank(relayer);
        election.submitAggregateSigned(agg, _signAggregate(K1_PK, agg));

        assertEq(election.aggregateDigest(), bytes32(0)); // not canonical yet

        // keyper2's identical signed aggregate reaches the quorum.
        vm.prank(relayer);
        election.submitAggregateSigned(agg, _signAggregate(K2_PK, agg));
        assertEq(
            election.aggregateDigest(),
            keccak256(abi.encodePacked("SHUTTER-GOVERNANCE-PROTOCOL-AGGREGATE-v1", election.electionId(), abi.encode(agg)))
        );
    }

    function test_submitAggregateSigned_rejectsNonKeyperSignature() external {
        bytes memory pk = _g2Point(1);
        bytes[] memory committee = _committee(10);
        vm.startPrank(relayer);
        election.voteDKGResultSigned(pk, committee, _signDkg(K1_PK, pk, committee));
        election.voteDKGResultSigned(pk, committee, _signDkg(K2_PK, pk, committee));
        vm.stopPrank();

        vm.warp(votingEnd);
        VotingTypes.EncryptedTally memory agg;
        agg.aggregates = _ciphertexts(70);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(ElectionBase.UnauthorizedKeyper.selector, vm.addr(OUTSIDER_PK)));
        election.submitAggregateSigned(agg, _signAggregate(OUTSIDER_PK, agg));
    }

    // -- signing helpers (mirror the contract digests) --------------------- #

    function _signAggregate(uint256 pk_, VotingTypes.EncryptedTally memory agg) private pure returns (bytes memory) {
        bytes32 digest =
            keccak256(abi.encodePacked("SHUTTER-GOVERNANCE-PROTOCOL-AGGREGATE-v1", uint256(1), abi.encode(agg)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk_, MessageHashUtils.toEthSignedMessageHash(digest));
        return abi.encodePacked(r, s, v);
    }

    function _ciphertexts(uint8 seed) private pure returns (VotingTypes.Ciphertext[] memory cts) {
        cts = new VotingTypes.Ciphertext[](3);
        cts[0] = VotingTypes.Ciphertext({c1: _g2Point(seed), c2: _g2Point(seed + 1)});
        cts[1] = VotingTypes.Ciphertext({c1: _g2Point(seed + 2), c2: _g2Point(seed + 3)});
        cts[2] = VotingTypes.Ciphertext({c1: _g2Point(seed + 4), c2: _g2Point(seed + 5)});
    }

    function _signDkg(uint256 pk_, bytes memory pkElection, bytes[] memory committee)
        private
        pure
        returns (bytes memory)
    {
        bytes32 digest = keccak256(
            abi.encodePacked("SHUTTER-GOVERNANCE-PROTOCOL-DKG-RESULT-v1", uint256(1), pkElection, abi.encode(committee))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk_, MessageHashUtils.toEthSignedMessageHash(digest));
        return abi.encodePacked(r, s, v);
    }

    function _signShare(uint256 pk_, bytes[] memory shares, VotingTypes.DLEQProof[] memory proofs)
        private
        pure
        returns (bytes memory)
    {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "SHUTTER-GOVERNANCE-PROTOCOL-DECRYPT-SHARE-v1", uint256(1), abi.encode(shares), abi.encode(proofs)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk_, MessageHashUtils.toEthSignedMessageHash(digest));
        return abi.encodePacked(r, s, v);
    }

    function _committee(uint8 seed) private pure returns (bytes[] memory c) {
        c = new bytes[](3);
        c[0] = _g2Point(seed);
        c[1] = _g2Point(seed + 1);
        c[2] = _g2Point(seed + 2);
    }

    function _shares(uint8 seed) private pure returns (bytes[] memory s) {
        s = new bytes[](3);
        s[0] = _g2Point(seed);
        s[1] = _g2Point(seed + 1);
        s[2] = _g2Point(seed + 2);
    }

    function _proofs(uint256 seed) private pure returns (VotingTypes.DLEQProof[] memory p) {
        p = new VotingTypes.DLEQProof[](3);
        p[0] = VotingTypes.DLEQProof({e: seed, z: seed + 1});
        p[1] = VotingTypes.DLEQProof({e: seed + 2, z: seed + 3});
        p[2] = VotingTypes.DLEQProof({e: seed + 4, z: seed + 5});
    }

    function _g2Point(uint8 seed) private pure returns (bytes memory point) {
        point = new bytes(96);
        for (uint256 i = 0; i < point.length; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            point[i] = bytes1(seed + uint8(i));
        }
    }

    function _params() private view returns (VotingTypes.ElectionParams memory) {
        return VotingTypes.ElectionParams({
            votingStart: votingStart,
            votingEnd: votingEnd,
            selfSubmitFee: 0,
            numCandidates: 3,
            budget: 1,
            mode: 0,
            variant: 0,
            weighted: false,
            scale: 1,
            duplicatePolicy: 1,
            protocolVersion: "v1",
            pkWR: bytes(""),
            resultPublisher: resultPublisher,
            voteProxy: voteProxy
        });
    }
}
