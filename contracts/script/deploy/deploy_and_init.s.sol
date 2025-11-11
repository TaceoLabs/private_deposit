// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {PrivateBalance} from "../../src/priv_balance.sol";
import {USDCToken} from "../../src/token.sol";

contract PrivateBalanceScript is Script {
    PrivateBalance public priv_balance;
    USDCToken public token;

    // MPC Public Keys
    PrivateBalance.BabyJubJubElement mpc_pk1 = PrivateBalance.BabyJubJubElement(
        18327386459449316261583862697000176637638391765809617634439462209982948418034,
        15354572660754000758598766963334959211735034910036035049973891316846535514308
    );
    PrivateBalance.BabyJubJubElement mpc_pk2 = PrivateBalance.BabyJubJubElement(
        12602421106157650455773350918246315481116064560358812084709638867737650728515,
        19806185260317599908779153797553700270051067264725027483113828383411852142438
    );
    PrivateBalance.BabyJubJubElement mpc_pk3 = PrivateBalance.BabyJubJubElement(
        21327735390005260722043380015729518050952199608547795714621193312072738959320,
        2321884067052636057092005455746434955998482736918020414679439547948463777586
    );

    uint256 public constant MAX_BALANCE = 2_000_000 ether;

    function setUp() public {}

    function run() public {
        address verifier = vm.envAddress("VERIFIER_ADDRESS");
        address poseidon2 = vm.envAddress("POSEIDON2_ADDRESS");
        address tokenAddress = vm.envAddress("TOKEN_ADDRESS");
        address mpcAddress = vm.envAddress("MPC_ADDRESS");
        address deployAddress = vm.envAddress("DEPLOYER_ADDRESS");

        token = USDCToken(tokenAddress);

        // Deploy Wallet
        vm.startBroadcast(deployAddress);
        priv_balance =
            new PrivateBalance(verifier, poseidon2, tokenAddress, mpcAddress, mpc_pk1, mpc_pk2, mpc_pk3, false);
        // Give tokens to MPC
        if (token.balanceOf(deployAddress) < MAX_BALANCE) {
            token.mint(address(mpcAddress), MAX_BALANCE);
        } else {
            token.transfer(mpcAddress, MAX_BALANCE);
        }
        vm.stopBroadcast();

        // MPC Wallet
        vm.startBroadcast(mpcAddress);
        token.approve(address(priv_balance), MAX_BALANCE);
        vm.stopBroadcast();

        console.log("PrivateBalance deployed to:", address(priv_balance));
    }
}
