// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {ConfidentialTokenERC} from "../../src/conf_token_erc.sol";

contract ConfidentialTokenERCScript is Script {
    ConfidentialTokenERC public conf_token;

    function setUp() public {
        address conf_token_address = vm.envAddress("CONF_TOKEN_ADDRESS");
        conf_token = ConfidentialTokenERC(conf_token_address);
    }

    function run() public {
        address receiver = vm.envAddress("ADDRESS");
        vm.startBroadcast();
        conf_token.retrieveFunds(receiver);
        vm.stopBroadcast();
    }
}
