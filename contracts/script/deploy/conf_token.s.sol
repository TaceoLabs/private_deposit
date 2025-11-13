// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {ConfidentialToken} from "../../src/conf_token.sol";

contract ConfidentialTokenScript is Script {
    ConfidentialToken public conf_token;

    // MPC Public Keys
    ConfidentialToken.BabyJubJubElement mpc_pk1 = ConfidentialToken.BabyJubJubElement(
        18327386459449316261583862697000176637638391765809617634439462209982948418034,
        15354572660754000758598766963334959211735034910036035049973891316846535514308
    );
    ConfidentialToken.BabyJubJubElement mpc_pk2 = ConfidentialToken.BabyJubJubElement(
        12602421106157650455773350918246315481116064560358812084709638867737650728515,
        19806185260317599908779153797553700270051067264725027483113828383411852142438
    );
    ConfidentialToken.BabyJubJubElement mpc_pk3 = ConfidentialToken.BabyJubJubElement(
        21327735390005260722043380015729518050952199608547795714621193312072738959320,
        2321884067052636057092005455746434955998482736918020414679439547948463777586
    );

    function setUp() public {}

    function run() public {
        address verifier = vm.envAddress("VERIFIER_ADDRESS");
        address poseidon2 = vm.envAddress("POSEIDON2_ADDRESS");
        address token = vm.envAddress("TOKEN_ADDRESS");
        address mpcAddress = vm.envAddress("MPC_ADDRESS");

        vm.startBroadcast();
        conf_token = new ConfidentialToken(verifier, poseidon2, token, mpcAddress, mpc_pk1, mpc_pk2, mpc_pk3, true);
        vm.stopBroadcast();

        console.log("ConfidentialToken deployed to:", address(conf_token));
    }
}
