// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {PrivateBalance} from "../src/priv_balance.sol";
import {Groth16Verifier} from "../src/groth16_verifier.sol";
import {Poseidon2T2_BN254} from "../src/poseidon2.sol";

contract PrivateBalanceScript is Script {
    PrivateBalance public priv_balance;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        Groth16Verifier verifier = new Groth16Verifier();
        Poseidon2T2_BN254 poseidon2 = new Poseidon2T2_BN254();
        address mpcAdress = address(0x4);

        // MPC Public Keys
        PrivateBalance.BabyJubJubElement memory mpc_pk1 = PrivateBalance
            .BabyJubJubElement(
                18327386459449316261583862697000176637638391765809617634439462209982948418034,
                15354572660754000758598766963334959211735034910036035049973891316846535514308
            );
        PrivateBalance.BabyJubJubElement memory mpc_pk2 = PrivateBalance
            .BabyJubJubElement(
                12602421106157650455773350918246315481116064560358812084709638867737650728515,
                19806185260317599908779153797553700270051067264725027483113828383411852142438
            );
        PrivateBalance.BabyJubJubElement memory mpc_pk3 = PrivateBalance
            .BabyJubJubElement(
                21327735390005260722043380015729518050952199608547795714621193312072738959320,
                2321884067052636057092005455746434955998482736918020414679439547948463777586
            );

        priv_balance = new PrivateBalance(
            address(verifier),
            address(poseidon2),
            mpcAdress,
            mpc_pk1,
            mpc_pk2,
            mpc_pk3
        );

        vm.stopBroadcast();
        console.log("Contract deployed at:", address(priv_balance));
    }
}
