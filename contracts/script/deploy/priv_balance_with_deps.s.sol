// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {PrivateBalance} from "../../src/priv_balance.sol";
import {Groth16Verifier} from "../../src/groth16_verifier.sol";
import {Poseidon2T2_BN254} from "../../src/poseidon2.sol";

contract PrivateBalanceWithDepsScript is Script {
    PrivateBalance public priv_balance;

    // MPC Public Keys
    PrivateBalance.BabyJubJubElement mpc_pk1 =
        PrivateBalance.BabyJubJubElement(
            18327386459449316261583862697000176637638391765809617634439462209982948418034,
            15354572660754000758598766963334959211735034910036035049973891316846535514308
        );
    PrivateBalance.BabyJubJubElement mpc_pk2 =
        PrivateBalance.BabyJubJubElement(
            12602421106157650455773350918246315481116064560358812084709638867737650728515,
            19806185260317599908779153797553700270051067264725027483113828383411852142438
        );
    PrivateBalance.BabyJubJubElement mpc_pk3 =
        PrivateBalance.BabyJubJubElement(
            21327735390005260722043380015729518050952199608547795714621193312072738959320,
            2321884067052636057092005455746434955998482736918020414679439547948463777586
        );

    function setUp() public {}

    function deployPoseidon2() public returns (address) {
        Poseidon2T2_BN254 poseidon2 = new Poseidon2T2_BN254();
        console.log("Poseidon2 deployed to:", address(poseidon2));
        return address(poseidon2);
    }

    function deployGroth16Verifier() public returns (address) {
        Groth16Verifier verifier = new Groth16Verifier();
        console.log("Groth16Verifier deployed to:", address(verifier));
        return address(verifier);
    }

    function run() public {
        address mpcAddress = vm.envAddress("MPC_ADDRESS");

        vm.startBroadcast();
        address verifier = deployGroth16Verifier();
        address poseidon2 = deployPoseidon2();
        priv_balance = new PrivateBalance(
            verifier,
            poseidon2,
            mpcAddress,
            mpc_pk1,
            mpc_pk2,
            mpc_pk3,
            true
        );
        vm.stopBroadcast();

        console.log("PrivateBalance deployed to:", address(priv_balance));
    }
}
