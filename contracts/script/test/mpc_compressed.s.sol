// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {ConfidentialToken} from "../../src/conf_token_compressed.sol";

contract ConfidentialTokenScript is Script {
    ConfidentialToken public conf_token;
    // The commitments
    uint256 beta = 12863605664522126046634765755549973856774488390013614199539072148585546495652;
    uint256 amount_commitment = 6122001814780532967242228952635820560915594353320782112285831468616175141938;
    uint256 alice_deposit_commitment = 10472730724950519210782735100119507791303697993456043905463698979794493049044;
    uint256 alice_transfer_commitment = 2349460248759906772457809891133094744847812413087153028369959863285798805431;
    uint256 bob_transfer_commitment = 1780328126052351031724742265038342844286261602142364299599894863345917791555;
    uint256 bob_withdraw_commitment = 9676308923541039172913703771221294985827720923273326758749501798863239137991;

    uint256 public constant BATCH_SIZE = 50;

    function setUp() public {
        address conf_token_address = vm.envAddress("CONF_TOKEN_ADDRESS");
        conf_token = ConfidentialToken(conf_token_address);
    }

    function run() public {
        // The proof
        ConfidentialToken.Groth16Proof memory proof;
        proof.pA = [
            17647018224873853425224693768050175056404109958761982169766632527597393942309,
            1493618428862152235102473084604192637833255444716416815815016434769778487914
        ];
        proof.pB = [
            [
                3193035001285274365883077547799483751154224202957669480645947876012935665131,
                1568872940681501605878003200701797982079256436724126665667186876968266546022
            ],
            [
                1056142230725582844638572826518857103614810001619640120440057739493465860758,
                5437709920501545643345720239928768019247520240369284638679291938942294000300
            ]
        ];
        proof.pC = [
            13431741745133477599618915618153853103107888952488523772479563012404938370906,
            11597207173047605668114787346017768066302255192945304841955862474353067644261
        ];

        // Process MPC actions
        // Create inputs
        ConfidentialToken.TransactionInputCompressed memory inputs;
        // Deposit by Alice
        inputs.action_index[0] = 1;
        // inputs.commitments[0] = 0;
        inputs.commitments[1] = alice_deposit_commitment;

        // Transfer from Alice to Bob
        inputs.action_index[1] = 2;
        inputs.commitments[2] = alice_transfer_commitment;
        inputs.commitments[3] = bob_transfer_commitment;

        // Withdraw by Bob
        inputs.action_index[2] = 3;
        inputs.commitments[4] = bob_withdraw_commitment;
        // inputs.commitments[5] = 0;

        // The Poseidon2 (sponge) hash of the commitments (used for UHF)
        inputs.beta = beta;

        // Dummies
        for (uint256 i = 3; i < BATCH_SIZE; i++) {
            // inputs.action_index[i] = 0;
            // inputs.commitments[i * 2] = 0;
            // inputs.commitments[i * 2 + 1] = 0;
        }

        vm.startBroadcast();
        conf_token.processMPC(inputs, proof);
        vm.stopBroadcast();
    }
}
