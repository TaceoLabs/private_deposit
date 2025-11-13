// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {ConfidentialToken} from "../../src/conf_token.sol";

contract ConfidentialTokenScript is Script {
    ConfidentialToken public conf_token;

    function setUp() public {
        address conf_token_address = vm.envAddress("CONF_TOKEN_ADDRESS");
        conf_token = ConfidentialToken(conf_token_address);
    }

    function run() public {
        address receiver = vm.envAddress("ADDRESS");
        vm.startBroadcast();
        conf_token.retrieveFunds(receiver);
        vm.stopBroadcast();
    }
}
