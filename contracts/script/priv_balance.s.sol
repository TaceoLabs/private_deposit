// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {PrivateBalance} from "../src/priv_balance.sol";

contract PrivateBalanceScript is Script {
    PrivateBalance public priv_balance;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        address mpcAdress = address(0x4);

        priv_balance = new PrivateBalance(mpcAdress);

        vm.stopBroadcast();
        console.log("Contract deployed at:", address(priv_balance));
    }
}
