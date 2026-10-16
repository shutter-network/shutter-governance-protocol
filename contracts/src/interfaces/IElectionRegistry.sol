// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IKeyperSet} from "./IKeyperSet.sol";
import {VotingTypes} from "../VotingTypes.sol";

interface IElectionRegistry is IAccessControl {
    event ElectionCreated(address indexed election, uint256 indexed electionId, address indexed keyperSet);

    function electionCount() external view returns (uint256);
    function elections(uint256 electionId) external view returns (address);
    function getElections(uint256 startElectionId, uint256 count) external view returns (address[] memory);
    function publishElection(IKeyperSet keyperSet, VotingTypes.ElectionParams calldata params)
        external
        returns (address electionAddr);
}
