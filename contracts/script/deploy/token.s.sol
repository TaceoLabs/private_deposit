// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {USDCToken} from "../../src/token.sol";

contract Groth16VerifierScript is Script {
    USDCToken public token;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        token = new USDCToken(1_000_000 ether);
        vm.stopBroadcast();
        console.log("Token deployed to:", address(token));
    }
}
