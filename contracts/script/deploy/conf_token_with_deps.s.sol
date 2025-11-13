// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {ConfidentialToken} from "../../src/conf_token.sol";
import {Groth16Verifier} from "../../src/groth16_verifier.sol";
import {Poseidon2T2_BN254} from "../../src/poseidon2.sol";
import {USDCToken} from "../../src/token.sol";

contract ConfidentialTokenWithDepsScript is Script {
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

    function deployToken() public returns (address) {
        USDCToken token = new USDCToken(10_000_000 ether);
        console.log("Token deployed to:", address(token));
        return address(token);
    }

    function run() public {
        address mpcAddress = vm.envAddress("MPC_ADDRESS");

        vm.startBroadcast();
        address verifier = deployGroth16Verifier();
        address poseidon2 = deployPoseidon2();
        address token = deployToken();
        conf_token = new ConfidentialToken(verifier, poseidon2, token, mpcAddress, mpc_pk1, mpc_pk2, mpc_pk3, true);

        USDCToken(token).approve(address(conf_token), type(uint256).max); // Approve all transactions for testing
        vm.stopBroadcast();

        console.log("ConfidentialToken deployed to:", address(conf_token));
    }
}
