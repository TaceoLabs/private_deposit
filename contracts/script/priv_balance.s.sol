// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {PrivateBalance} from "../src/priv_balance.sol";
import {Groth16Verifier} from "../src/groth16_verifier.sol";

contract PrivateBalanceScript is Script {
    PrivateBalance public priv_balance;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        Groth16Verifier verifier = new Groth16Verifier();
        address mpcAdress = address(0x4);

        priv_balance = new PrivateBalance(address(verifier), mpcAdress);

        vm.stopBroadcast();
        console.log("Contract deployed at:", address(priv_balance));
    }
}
