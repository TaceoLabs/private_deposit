// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {USDCToken} from "../../src/token.sol";

contract PrivateBalanceScript is Script {
    USDCToken public token;

    function setUp() public {
        address token_address = vm.envAddress("TOKEN_ADDRESS");
        token = USDCToken(token_address);
    }

    function run() public {
        address priv_balance_address = vm.envAddress("PRIV_BALANCE_ADDRESS");
        vm.startBroadcast();
        token.approve(priv_balance_address, 1 ether);
        vm.stopBroadcast();
    }
}
