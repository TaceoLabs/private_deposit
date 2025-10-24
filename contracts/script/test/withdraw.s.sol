// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {PrivateBalance} from "../../src/priv_balance.sol";

contract PrivateBalanceScript is Script {
    PrivateBalance public priv_balance;

    function setUp() public {
        address priv_balance_address = vm.envAddress("PRIV_BALANCE_ADDRESS");
        priv_balance = PrivateBalance(priv_balance_address);
    }

    function run() public {
        vm.startBroadcast();
        uint256 index = priv_balance.withdraw(1 ether);
        vm.stopBroadcast();

        console.log("Withdraw registered at index", index);
    }
}
