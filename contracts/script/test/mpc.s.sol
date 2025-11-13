// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {ConfidentialToken} from "../../src/conf_token.sol";

contract ConfidentialTokenScript is Script {
    ConfidentialToken public conf_token;

    // The commitments
    uint256 amount_commitment = 6122001814780532967242228952635820560915594353320782112285831468616175141938;
    uint256 alice_deposit_commitment = 3201987479688239509622843041340904888864617707265452669487517581782057438896;
    uint256 alice_transfer_commitment = 15368533223277346855472209984555584829872777522463312540816402098111235877055;
    uint256 bob_transfer_commitment = 7864704766370736818749892705108497259949033020281775668007367478500968272692;
    uint256 bob_withdraw_commitment = 13215961508686837023384776374239202933726030231749068377927862602099601546864;

    uint256 public constant BATCH_SIZE = 50;

    function setUp() public {
        address conf_token_address = vm.envAddress("CONF_TOKEN_ADDRESS");
        conf_token = ConfidentialToken(conf_token_address);
    }

    function run() public {
        // The proof
        ConfidentialToken.Groth16Proof memory proof;
        proof.pA = [
            2692155549328219733881864725659782103889366503314143192616415429475023216338,
            7397719695643597255965727699285533576443852083251336234356429231072669662021
        ];
        proof.pB = [
            [
                21608824428506851514496265369804648481470242600371853926004695916981103788160,
                11596174681855428976040607109588308667317820550251283980191366963834400832732
            ],
            [
                11083725302752237458855860622956225234109480212891402060116337709257281360707,
                6347930192728274588828144611766734633734516022267475754558612691312042156070
            ]
        ];
        proof.pC = [
            16515820955573077081176603193172471949903389540762943567544234515017768125593,
            15121740901547515108698594054061130400946065862855884564613333703216272288574
        ];

        // Process MPC actions
        // Create inputs
        ConfidentialToken.TransactionInput memory inputs;
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
