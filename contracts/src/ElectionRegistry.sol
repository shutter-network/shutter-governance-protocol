// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ElectionDeployer} from "./ElectionDeployer.sol";
import {IElectionRegistry} from "./interfaces/IElectionRegistry.sol";
import {IKeyperSet} from "./interfaces/IKeyperSet.sol";
import {VotingTypes} from "./VotingTypes.sol";

/// @notice Admin-gated factory + index of Election instances (scaffold only).
contract ElectionRegistry is AccessControl, IElectionRegistry {
    error InvalidKeyperSet();

    uint256 public electionCount;
    mapping(uint256 => address) public elections;

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /// @notice Publish an election under the next sequential id.
    /// @dev electionId is assigned by the registry (++electionCount), matching the
    ///      canonical bulletin-board model — ids are dense and enumerable, and no
    ///      caller-chosen id is accepted.
    function publishElection(IKeyperSet keyperSet, VotingTypes.ElectionParams calldata params)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
        returns (address electionAddr)
    {
        return _publishElection(msg.sender, keyperSet, params);
    }

    function _publishElection(address admin, IKeyperSet keyperSet, VotingTypes.ElectionParams calldata params)
        private
        returns (address electionAddr)
    {
        uint64 numMembers = keyperSet.getNumMembers();
        uint64 threshold = keyperSet.getThreshold();
        if (numMembers == 0 || threshold == 0 || threshold > numMembers) {
            revert InvalidKeyperSet();
        }

        uint256 electionId = ++electionCount;
        // Deploy via the linked library so Election's ~22 KB creation code lives in the
        // library, not the registry — keeps the registry under EIP-170. DELEGATECALL, so
        // the Election is still created in (and owned by) this registry's context.
        electionAddr = ElectionDeployer.deploy(admin, electionId, keyperSet, params);
        elections[electionId] = electionAddr;
        emit ElectionCreated(electionAddr, electionId, address(keyperSet));
    }

    function getElections(uint256 startElectionId, uint256 count) external view returns (address[] memory result) {
        result = new address[](count);
        for (uint256 index = 0; index < count; index++) {
            result[index] = elections[startElectionId + index];
        }
    }
}
