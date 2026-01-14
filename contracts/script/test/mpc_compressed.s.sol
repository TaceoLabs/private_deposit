// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {ConfidentialToken} from "../../src/conf_token_compressed.sol";

contract ConfidentialTokenScript is Script {
    ConfidentialToken public conf_token;

    // The commitments
    uint256 beta =
        9647565638924250332879721163670572277074814087177945098807985524659888766988;
    uint256 amount_commitment =
        6122001814780532967242228952635820560915594353320782112285831468616175141938;
    uint256 alice_deposit_commitment =
        14471757854728448127825347331265959861817408583828130696223192146179326752021;
    uint256 alice_transfer_commitment =
        11831906438633052849708999674948823485253050075139677619556607993904857789163;
    uint256 bob_transfer_commitment =
        15672919386761407505329106520336544854105844265217886841456443363675882718008;
    uint256 bob_withdraw_commitment =
        1579296041954237025898498774965933453733589109813422879619729059353394838454;

    uint256 public constant BATCH_SIZE = 50;

    function setUp() public {
        address conf_token_address = vm.envAddress("CONF_TOKEN_ADDRESS");
        conf_token = ConfidentialToken(conf_token_address);
    }

    function run() public {
        // The proof
        ConfidentialToken.Groth16Proof memory proof;
        proof.pA = [
            13018128679997624095174323388591191617226569257349572960249012526309450629092,
            15982356683995091247597193298446872706655828626933899066068339322269329585274
        ];
        proof.pB = [
            [
                6677826691292417249336418272931169828416853173795149577276408809996274849765,
                8155643985684641203695469869725412327905432596722749886989177675228393467302
            ],
            [
                2760630800707964627409818114836503817399488915011587925751086552414354618311,
                2329308084996965589311509181467670311769799745147244136917038699204863781481
            ]
        ];
        proof.pC = [
            7231002839039142343240435060114508217061351923177504574422657603421733710638,
            12238114363114386566083344488042241317964053622318731149797495672044755822601
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
