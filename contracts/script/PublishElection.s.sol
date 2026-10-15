// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";

import {Election} from "../src/Election.sol";
import {ElectionRegistry} from "../src/ElectionRegistry.sol";
import {IKeyperSet} from "../src/interfaces/IKeyperSet.sol";
import {VotingTypes} from "../src/VotingTypes.sol";

/// @notice Publish a generalised election via `ElectionRegistry.publishElection`
///         (the shutter_governance_protocol ElectionDataLayer path). The electionId is assigned by the
///         registry (next sequential id — the canonical bulletin-board model) and
///         reported in the logs; callers read it back rather than choosing it.
///
/// All generalised config fields are read from env with sensible defaults:
///
///   REGISTRY, KEYPER_SET, PRIVATE_KEY    required
///   VOTING_START, VOTING_END             required
///   NUM_CANDIDATES, BUDGET               required
///   MODE (0=exact,1=atMost)              default 0
///   VARIANT (0=A,1=B)                    default 0
///   WEIGHTED (bool)                      default false
///   SCALE                                default 1
///   DUPLICATE_POLICY (0=first,1=last)    default 1
///   PROTOCOL_VERSION (string)            default "SHUTTER-VOTE-v1"
///   PK_WR (bytes)                        required — eligibility public key
///   RESULT_PUBLISHER, VOTE_PROXY         required
///   SELF_SUBMIT_FEE                      default 0
contract PublishElection is Script {
    error InvalidVotingWindow(uint256 votingStart, uint256 votingEnd);
    error ValueTooLarge(string name, uint256 value, uint256 maxValue);

    function run() external returns (address electionAddr) {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address registryAddr = vm.envAddress("REGISTRY");
        address keyperSetAddr = vm.envAddress("KEYPER_SET");

        uint64 votingStart = _toUint64("VOTING_START", vm.envUint("VOTING_START"));
        uint64 votingEnd = _toUint64("VOTING_END", vm.envUint("VOTING_END"));
        if (votingEnd <= votingStart) revert InvalidVotingWindow(votingStart, votingEnd);

        VotingTypes.ElectionParams memory params = VotingTypes.ElectionParams({
            votingStart: votingStart,
            votingEnd: votingEnd,
            selfSubmitFee: vm.envOr("SELF_SUBMIT_FEE", uint256(0)),
            numCandidates: _toUint32("NUM_CANDIDATES", vm.envUint("NUM_CANDIDATES")),
            budget: _toUint32("BUDGET", vm.envUint("BUDGET")),
            mode: _toUint8("MODE", vm.envOr("MODE", uint256(0))),
            variant: _toUint8("VARIANT", vm.envOr("VARIANT", uint256(0))),
            weighted: vm.envOr("WEIGHTED", false),
            scale: vm.envOr("SCALE", uint256(1)),
            duplicatePolicy: _toUint8("DUPLICATE_POLICY", vm.envOr("DUPLICATE_POLICY", uint256(1))),
            protocolVersion: vm.envOr("PROTOCOL_VERSION", string("SHUTTER-VOTE-v1")),
            pkWR: vm.envBytes("PK_WR"),
            resultPublisher: vm.envAddress("RESULT_PUBLISHER"),
            voteProxy: vm.envAddress("VOTE_PROXY")
        });

        vm.startBroadcast(pk);
        electionAddr = ElectionRegistry(registryAddr).publishElection(IKeyperSet(keyperSetAddr), params);
        vm.stopBroadcast();

        console2.log("Election deployed:", electionAddr);
        console2.log("Election ID (assigned):", Election(payable(electionAddr)).electionId());
        console2.log("Result Publisher:", params.resultPublisher);
        console2.log("Vote proxy:", params.voteProxy);
    }

    function _toUint64(string memory name, uint256 value) private pure returns (uint64 result) {
        if (value > type(uint64).max) revert ValueTooLarge(name, value, type(uint64).max);
        // forge-lint: disable-next-line(unsafe-typecast)
        result = uint64(value);
    }

    function _toUint32(string memory name, uint256 value) private pure returns (uint32 result) {
        if (value > type(uint32).max) revert ValueTooLarge(name, value, type(uint32).max);
        // forge-lint: disable-next-line(unsafe-typecast)
        result = uint32(value);
    }

    function _toUint8(string memory name, uint256 value) private pure returns (uint8 result) {
        if (value > type(uint8).max) revert ValueTooLarge(name, value, type(uint8).max);
        // forge-lint: disable-next-line(unsafe-typecast)
        result = uint8(value);
    }
}

