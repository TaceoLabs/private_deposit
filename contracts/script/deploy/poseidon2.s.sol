// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {Poseidon2T2_BN254} from "../../src/poseidon2.sol";

contract Poseidon2Script is Script {
    Poseidon2T2_BN254 public poseidon2;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        poseidon2 = new Poseidon2T2_BN254();
        vm.stopBroadcast();
        console.log("Poseidon2T2_BN254 deployed to:", address(poseidon2));
    }
}
