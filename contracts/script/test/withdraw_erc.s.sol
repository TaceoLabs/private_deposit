// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {ConfidentialTokenERC} from "../../src/conf_token.sol";

contract ConfidentialTokenERCScript is Script {
    ConfidentialTokenERC public conf_token;

    function setUp() public {
        address conf_token_address = vm.envAddress("CONF_TOKEN_ADDRESS");
        conf_token = ConfidentialTokenERC(conf_token_address);
    }

    function run() public {
        vm.startBroadcast();
        uint256 index = conf_token.withdraw(1 ether);
        vm.stopBroadcast();

        console.log("Withdraw registered at index", index);
    }
}
