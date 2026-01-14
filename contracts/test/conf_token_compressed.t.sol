// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {ConfidentialToken} from "../src/conf_token_compressed.sol";
import {Action, ActionQuery} from "../src/action_vector.sol";
import {Groth16Verifier} from "../src/groth16_verifier_compressed.sol";
import {Poseidon2T2_BN254} from "../src/poseidon2.sol";

contract ConfidentialTokenCompressedTest is Test {
    ConfidentialToken public conf_token;
    Groth16Verifier public verifier;
    Poseidon2T2_BN254 public poseidon2;

    address alice = address(0x1);
    address bob = address(0x2);
    address mpcAdress = address(0x4);

    // MPC Public Keys
    ConfidentialToken.BabyJubJubElement mpc_pk1 =
        ConfidentialToken.BabyJubJubElement(
            18327386459449316261583862697000176637638391765809617634439462209982948418034,
            15354572660754000758598766963334959211735034910036035049973891316846535514308
        );
    ConfidentialToken.BabyJubJubElement mpc_pk2 =
        ConfidentialToken.BabyJubJubElement(
            12602421106157650455773350918246315481116064560358812084709638867737650728515,
            19806185260317599908779153797553700270051067264725027483113828383411852142438
        );
    ConfidentialToken.BabyJubJubElement mpc_pk3 =
        ConfidentialToken.BabyJubJubElement(
            21327735390005260722043380015729518050952199608547795714621193312072738959320,
            2321884067052636057092005455746434955998482736918020414679439547948463777586
        );

    // Sender Public Key
    ConfidentialToken.BabyJubJubElement sender_key =
        ConfidentialToken.BabyJubJubElement(
            14126526673002152226685028859637341993398518531603040589075929701947081008152,
            2262429687539372424558773003960644901192543279316913065087518967280725694787
        );

    // Ciphertext components
    uint256 amount0 =
        4905774193859250633367103010011164286351164406878957297441473790037983418652;
    uint256 r0 =
        21386148726158425328415803708635161530955724864871919339801760063789425854042;
    uint256 amount1 =
        20287032784938589294727054070772132499956033880369988115096570893732088478341;
    uint256 r1 =
        2517106720126313632299138440935051367221304808062364863107679786545605031704;
    uint256 amount2 =
        9318907414941246766382086462820299264561576095244169207256108475923746065863;
    uint256 r2 =
        19408893814710241131916645829673431006471358670475695934923536001569549968187;

    ConfidentialToken.Ciphertext ciphertext =
        ConfidentialToken.Ciphertext(
            [amount0, amount1, amount2],
            [r0, r1, r2],
            sender_key
        );

    uint256 public constant BATCH_SIZE = 50;

    function deal_tokens(address to, uint256 amount) internal {
        vm.deal(to, amount);
    }

    function setUp() public {
        verifier = new Groth16Verifier();
        poseidon2 = new Poseidon2T2_BN254();

        conf_token = new ConfidentialToken(
            address(verifier),
            address(poseidon2),
            mpcAdress,
            mpc_pk1,
            mpc_pk2,
            mpc_pk3,
            true
        );
    }

    function testRetrieveFunds() public {
        deal_tokens(address(this), 10 ether);
        conf_token.deposit{value: 1 ether}();
        assertEq(address(conf_token).balance, 1 ether);

        vm.expectRevert();
        conf_token.retrieveFunds(address(mpcAdress));

        vm.startPrank(mpcAdress);
        conf_token.retrieveFunds(address(mpcAdress));
        vm.stopPrank();

        assertEq(address(conf_token).balance, 0);
        assertEq(address(mpcAdress).balance, 1 ether);
    }

    function testDeposit() public {
        deal_tokens(address(this), 10 ether);
        uint256 index = conf_token.deposit{value: 1 ether}();
        console.log("Deposit action added at index:", index);

        ActionQuery memory query = conf_token.getActionAtIndex(index);
        assertEq(uint256(query.action), uint256(Action.Deposit));
        assertEq(query.receiver, address(this));
        assertEq(query.sender, address(0));
        assertEq(query.amount, 1 ether);
    }

    function testWithdraw() public {
        uint256 index = conf_token.withdraw(1 ether);
        console.log("Withdraw action added at index:", index);

        ActionQuery memory query = conf_token.getActionAtIndex(index);
        assertEq(uint256(query.action), uint256(Action.Withdraw));
        assertEq(query.sender, address(this));
        assertEq(query.receiver, address(0));
        assertEq(query.amount, 1 ether);
    }

    function testTransfer() public {
        uint256 commit = conf_token.commit(1 ether, 123);
        uint256 index = conf_token.transfer(mpcAdress, commit, ciphertext);
        console.log("Transaction action added at index:", index);

        ConfidentialToken.Ciphertext memory cipher = conf_token
            .getCiphertextAtIndex(index);
        assertNotEq(cipher.amount[0], 0);

        ActionQuery memory query = conf_token.getActionAtIndex(index);
        assertEq(uint256(query.action), uint256(Action.Transfer));
        assertEq(query.sender, address(this));
        assertEq(query.receiver, mpcAdress);
        assertEq(query.amount, commit);
    }

    function testRemoveAction() public {
        uint256 index = conf_token.withdraw(1 ether);
        console.log("Withdraw action added at index:", index);

        ActionQuery memory query = conf_token.getActionAtIndex(index);
        assertEq(uint256(query.action), uint256(Action.Withdraw));
        assertEq(query.sender, address(this));
        assertEq(query.receiver, address(0));
        assertEq(query.amount, 1 ether);

        vm.expectRevert();
        conf_token.removeActionAtIndex(index);

        vm.startPrank(mpcAdress);
        conf_token.removeActionAtIndex(index);
        vm.stopPrank();

        query = conf_token.getActionAtIndex(index);
        assertEq(uint256(query.action), uint256(Action.Invalid));
        assertEq(query.sender, address(0));
        assertEq(query.receiver, address(0));
        assertEq(query.amount, 0);
    }

    function testProcessMPC() public {
        uint256 amount = 1 ether;
        ///////////////////////////////////////////////////////////////////////
        // Take the following part from the testcases generation script
        ///////////////////////////////////////////////////////////////////////
        // The commitments
        uint256 beta = 9647565638924250332879721163670572277074814087177945098807985524659888766988;
        uint256 amount_commitment = 6122001814780532967242228952635820560915594353320782112285831468616175141938;
        uint256 alice_deposit_commitment = 14471757854728448127825347331265959861817408583828130696223192146179326752021;
        uint256 alice_transfer_commitment = 11831906438633052849708999674948823485253050075139677619556607993904857789163;
        uint256 bob_transfer_commitment = 15672919386761407505329106520336544854105844265217886841456443363675882718008;
        uint256 bob_withdraw_commitment = 1579296041954237025898498774965933453733589109813422879619729059353394838454;

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
        ///////////////////////////////////////////////////////////////////////

        // Initial balances
        assertEq(bob.balance, 0);
        deal_tokens(alice, amount);

        // Actions
        vm.startPrank(alice);
        uint256 index_ = conf_token.deposit{value: amount}();
        console.log("Deposit action added at index:", index_);
        uint256 index = conf_token.transfer(bob, amount_commitment, ciphertext);
        console.log("Transfer action added at index:", index);
        vm.stopPrank();

        vm.startPrank(bob);
        index_ = conf_token.withdraw(amount);
        console.log("Withdraw action added at index:", index_);
        vm.stopPrank();

        // Check that ciphertexts are stored correctly
        ConfidentialToken.Ciphertext memory cipher = conf_token
            .getCiphertextAtIndex(index);
        assertNotEq(cipher.amount[0], 0);

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
        console.log("Processing MPC actions...");
        vm.startPrank(mpcAdress);
        conf_token.processMPC(inputs, proof);
        vm.stopPrank();

        assertEq(address(conf_token).balance, 0);
        assertEq(alice.balance, 0);
        assertEq(bob.balance, amount);

        assertEq(conf_token.getActionQueueSize(), 1);

        cipher = conf_token.getCiphertextAtIndex(index);
        // assertEq(cipher.amount[0], 0); // We don't remove anymore, since it costs more gas
    }
}
