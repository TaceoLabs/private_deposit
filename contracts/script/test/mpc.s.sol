// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {PrivateBalance} from "../../src/priv_balance.sol";

contract PrivateBalanceScript is Script {
    PrivateBalance public priv_balance;

    // The commitments
    uint256 amount_commitment =
        15593109598059662780184338689081921601599342431766556349154126622647806139894;
    uint256 alice_deposit_commitment =
        19685613928254773430958320879854539957988000567954309699598309756646459490330;
    uint256 alice_transfer_commitment =
        18814066358174324635681792444252743289132491162090717728068571031091132563248;
    uint256 bob_transfer_commitment =
        2877422310132332944474085930393061598983531728861024930009012454210466348665;
    uint256 bob_withdraw_commitment =
        2820648692777157593761309070953557618636319812063507921350841127406188112384;

    uint public constant BATCH_SIZE = 96;

    function setUp() public {
        address priv_balance_address = vm.envAddress("PRIV_BALANCE_ADDRESS");
        priv_balance = PrivateBalance(priv_balance_address);
    }

    function run() public {
        // The proof
        PrivateBalance.Groth16Proof memory proof;
        proof.pA = [
            7662581001532611800422339357493416976540067465029445424933508989387189326225,
            18260175797310210227694683514312327848457592159288477676186382573979463102878
        ];
        proof.pB = [
            [
                14223167106500608940455960871836946875250303292058424038516958981119056177912,
                13174189992942246887725548858935822925538093963332589419326801823327797441831
            ],
            [
                20191030468749870484155662919316582565991943025965349219830744305839976521194,
                17208709266630031275544760274071387126363640035308857651397699185628282010607
            ]
        ];
        proof.pC = [
            17048778387825973649319193195461780800588200638466925925638135820032859271853,
            494094633875766853543888222789719679931645692185749379518382071443874555571
        ];

        // Process MPC actions
        // Create inputs
        PrivateBalance.TransactionInput memory inputs;
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
        priv_balance.processMPC(inputs, proof);
        vm.stopBroadcast();
    }
}
