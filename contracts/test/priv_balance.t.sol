// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {PrivateBalance} from "../src/priv_balance.sol";
import {Action, ActionQuery} from "../src/action_vector.sol";
import {Groth16Verifier} from "../src/groth16_verifier.sol";
import {Poseidon2T2_BN254} from "../src/poseidon2.sol";
import {USDCToken} from "../src/token.sol";

contract PrivateBalanceTest is Test {
    PrivateBalance public priv_balance;
    Groth16Verifier public verifier;
    Poseidon2T2_BN254 public poseidon2;
    USDCToken public token;

    address alice = address(0x1);
    address bob = address(0x2);
    address mpcAdress = address(0x4);

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

    // For a transfer action
    // Sender Public Key
    PrivateBalance.BabyJubJubElement sender_key = PrivateBalance.BabyJubJubElement(
        14126526673002152226685028859637341993398518531603040589075929701947081008152,
        2262429687539372424558773003960644901192543279316913065087518967280725694787
    );

    // Ciphertext components
    uint256 amount0 = 4905774193859250633367103010011164286351164406878957297441473790037983418652;
    uint256 r0 = 21386148726158425328415803708635161530955724864871919339801760063789425854042;
    uint256 amount1 = 20287032784938589294727054070772132499956033880369988115096570893732088478341;
    uint256 r1 = 2517106720126313632299138440935051367221304808062364863107679786545605031704;
    uint256 amount2 = 9318907414941246766382086462820299264561576095244169207256108475923746065863;
    uint256 r2 = 19408893814710241131916645829673431006471358670475695934923536001569549968187;

    PrivateBalance.Ciphertext ciphertext =
        PrivateBalance.Ciphertext([amount0, amount1, amount2], [r0, r1, r2], sender_key);

    uint256 public constant BATCH_SIZE = 50;

    function deal_tokens(address to, uint256 amount) internal {
        // vm.deal(to, amount);
        token.transfer(to, amount);
    }

    function give_allowance(address from, address to, uint256 amount) internal {
        vm.startPrank(from);
        token.approve(to, amount);
        vm.stopPrank();
    }

    function setUp() public {
        verifier = new Groth16Verifier();
        poseidon2 = new Poseidon2T2_BN254();
        token = new USDCToken(1_000_000 ether);

        priv_balance = new PrivateBalance(
            address(verifier), address(poseidon2), address(token), mpcAdress, mpc_pk1, mpc_pk2, mpc_pk3, true
        );

        give_allowance(address(this), address(priv_balance), type(uint256).max);
        give_allowance(alice, address(priv_balance), type(uint256).max);
    }

    function testRetrieveFunds() public {
        deal_tokens(address(this), 10 ether);
        priv_balance.deposit(1 ether);
        assertEq(token.balanceOf(address(priv_balance)), 1 ether);
        // priv_balance.deposit{value: 1 ether}();

        vm.expectRevert();
        priv_balance.retrieveFunds();

        vm.startPrank(mpcAdress);
        priv_balance.retrieveFunds();
        vm.stopPrank();

        // assertEq(address(priv_balance).balance, 0);
        // assertEq(address(mpcAdress).balance, 1 ether);
        assertEq(token.balanceOf(address(priv_balance)), 0);
        assertEq(token.balanceOf(address(mpcAdress)), 1 ether);
    }

    function testDeposit() public {
        deal_tokens(address(this), 10 ether);
        uint256 index = priv_balance.deposit(1 ether);
        // uint256 index = priv_balance.deposit{value: 1 ether}();
        console.log("Deposit action added at index:", index);

        ActionQuery memory query = priv_balance.getActionAtIndex(index);
        assertEq(uint256(query.action), uint256(Action.Deposit));
        assertEq(query.receiver, address(this));
        assertEq(query.sender, address(0));
        assertEq(query.amount, 1 ether);
    }

    function testWithdraw() public {
        uint256 index = priv_balance.withdraw(1 ether);
        console.log("Withdraw action added at index:", index);

        ActionQuery memory query = priv_balance.getActionAtIndex(index);
        assertEq(uint256(query.action), uint256(Action.Withdraw));
        assertEq(query.sender, address(this));
        assertEq(query.receiver, address(0));
        assertEq(query.amount, 1 ether);
    }

    function testTransfer() public {
        uint256 commit = priv_balance.commit(1 ether, 123);
        uint256 index = priv_balance.transfer(mpcAdress, commit, ciphertext);
        console.log("Transaction action added at index:", index);

        PrivateBalance.Ciphertext memory cipher = priv_balance.getCiphertextAtIndex(index);
        assertNotEq(cipher.amount[0], 0);

        ActionQuery memory query = priv_balance.getActionAtIndex(index);
        assertEq(uint256(query.action), uint256(Action.Transfer));
        assertEq(query.sender, address(this));
        assertEq(query.receiver, mpcAdress);
        assertEq(query.amount, commit);
    }

    function testRemoveAction() public {
        uint256 index = priv_balance.withdraw(1 ether);
        console.log("Withdraw action added at index:", index);

        ActionQuery memory query = priv_balance.getActionAtIndex(index);
        assertEq(uint256(query.action), uint256(Action.Withdraw));
        assertEq(query.sender, address(this));
        assertEq(query.receiver, address(0));
        assertEq(query.amount, 1 ether);

        vm.expectRevert();
        priv_balance.removeActionAtIndex(index);

        vm.startPrank(mpcAdress);
        priv_balance.removeActionAtIndex(index);
        vm.stopPrank();

        query = priv_balance.getActionAtIndex(index);
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
        uint256 amount_commitment = 6122001814780532967242228952635820560915594353320782112285831468616175141938;
        uint256 alice_deposit_commitment = 3201987479688239509622843041340904888864617707265452669487517581782057438896;
        uint256 alice_transfer_commitment =
            15368533223277346855472209984555584829872777522463312540816402098111235877055;
        uint256 bob_transfer_commitment = 7864704766370736818749892705108497259949033020281775668007367478500968272692;
        uint256 bob_withdraw_commitment = 13215961508686837023384776374239202933726030231749068377927862602099601546864;

        // The proof
        PrivateBalance.Groth16Proof memory proof;
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
        ///////////////////////////////////////////////////////////////////////

        // Initial balances
        assertEq(bob.balance, 0);
        deal_tokens(alice, amount);

        // Actions
        vm.startPrank(alice);
        // uint256 index_ = priv_balance.deposit{value: amount}();
        uint256 index_ = priv_balance.deposit(amount);
        console.log("Deposit action added at index:", index_);
        uint256 index = priv_balance.transfer(bob, amount_commitment, ciphertext);
        console.log("Transfer action added at index:", index);
        vm.stopPrank();

        vm.startPrank(bob);
        index_ = priv_balance.withdraw(amount);
        console.log("Withdraw action added at index:", index_);
        vm.stopPrank();

        // Check that ciphertexts are stored correctly
        PrivateBalance.Ciphertext memory cipher = priv_balance.getCiphertextAtIndex(index);
        assertNotEq(cipher.amount[0], 0);

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

        vm.startPrank(mpcAdress);
        priv_balance.processMPC(inputs, proof);
        vm.stopPrank();

        // assertEq(address(priv_balance).balance, 0);
        // assertEq(alice.balance, 0);
        // assertEq(bob.balance, amount);
        assertEq(token.balanceOf(address(priv_balance)), 0);
        assertEq(token.balanceOf(alice), 0);
        assertEq(token.balanceOf(bob), amount);

        assertEq(priv_balance.getActionQueueSize(), 1);

        cipher = priv_balance.getCiphertextAtIndex(index);
        // assertEq(cipher.amount[0], 0); // We don't remove anymore, since it costs more gas
    }
}
