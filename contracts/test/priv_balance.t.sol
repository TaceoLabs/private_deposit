// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {PrivateBalance} from "../src/priv_balance.sol";
import {Action, ActionQuery} from "../src/action_queue.sol";
import {Groth16Verifier} from "../src/groth16_verifier.sol";

contract PrivateBalanceTest is Test {
    PrivateBalance public priv_balance;
    Groth16Verifier public verifier;

    address mpcAdress = address(0x4);

    uint public constant BATCH_SIZE = 96;

    function setUp() public {
        verifier = new Groth16Verifier();
        priv_balance = new PrivateBalance(address(verifier), mpcAdress);
    }

    function testRetrieveFunds() public {
        vm.deal(address(this), 10 ether);
        priv_balance.deposit{value: 1 ether}();

        vm.expectRevert();
        priv_balance.retrieveFunds();

        vm.startPrank(mpcAdress);
        priv_balance.retrieveFunds();
        vm.stopPrank();

        assertEq(address(priv_balance).balance, 0);
        assertEq(address(mpcAdress).balance, 1 ether);
    }

    function testDeposit() public {
        vm.deal(address(this), 10 ether);
        uint256 index = priv_balance.deposit{value: 1 ether}();
        console.log("Deposit action added at index:", index);

        ActionQuery memory query = priv_balance.getActionAtIndex(index);
        assertEq(uint(query.action), uint(Action.Deposit));
        assertEq(query.receiver, address(this));
        assertEq(query.sender, address(0));
        assertEq(query.amount, 1 ether);
    }

    function testWithdraw() public {
        uint256 index = priv_balance.withdraw(1 ether);
        console.log("Withdraw action added at index:", index);

        ActionQuery memory query = priv_balance.getActionAtIndex(index);
        assertEq(uint(query.action), uint(Action.Withdraw));
        assertEq(query.sender, address(this));
        assertEq(query.receiver, address(0));
        assertEq(query.amount, 1 ether);
    }

    function testTransfer() public {
        uint256 commit = priv_balance.commit(1 ether, 123);
        uint256 index = priv_balance.transfer(mpcAdress, commit);
        console.log("Transaction action added at index:", index);

        ActionQuery memory query = priv_balance.getActionAtIndex(index);
        assertEq(uint(query.action), uint(Action.Transfer));
        assertEq(query.sender, address(this));
        assertEq(query.receiver, mpcAdress);
        assertEq(query.amount, commit);
    }

    function testRemoveAction() public {
        uint256 index = priv_balance.withdraw(1 ether);
        console.log("Withdraw action added at index:", index);

        ActionQuery memory query = priv_balance.getActionAtIndex(index);
        assertEq(uint(query.action), uint(Action.Withdraw));
        assertEq(query.sender, address(this));
        assertEq(query.receiver, address(0));
        assertEq(query.amount, 1 ether);

        vm.expectRevert();
        priv_balance.removeActionAtIndex(index);

        vm.startPrank(mpcAdress);
        priv_balance.removeActionAtIndex(index);
        vm.stopPrank();

        query = priv_balance.getActionAtIndex(index);
        assertEq(uint(query.action), uint(Action.Invalid));
        assertEq(query.sender, address(0));
        assertEq(query.receiver, address(0));
        assertEq(query.amount, 0);
    }

    function testProcessMPC() public {
        address alice = address(0x1);
        address bob = address(0x2);

        uint256 amount = 1 ether;
        ///////////////////////////////////////////////////////////////////////
        // Take the following part from the testcases generation script
        ///////////////////////////////////////////////////////////////////////
        // The commitments
        uint256 amount_commitment = 15593109598059662780184338689081921601599342431766556349154126622647806139894;
        uint256 alice_deposit_commitment = 19685613928254773430958320879854539957988000567954309699598309756646459490330;
        uint256 alice_transfer_commitment = 18814066358174324635681792444252743289132491162090717728068571031091132563248;
        uint256 bob_transfer_commitment = 2877422310132332944474085930393061598983531728861024930009012454210466348665;
        uint256 bob_withdraw_commitment = 2820648692777157593761309070953557618636319812063507921350841127406188112384;

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
        ///////////////////////////////////////////////////////////////////////

        // Initial balances
        assertEq(bob.balance, 0);
        vm.deal(alice, amount);

        // Actions
        vm.startPrank(alice);
        priv_balance.deposit{value: amount}();
        priv_balance.transfer(bob, amount_commitment);
        vm.stopPrank();

        vm.startPrank(bob);
        priv_balance.withdraw(amount);
        vm.stopPrank();

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

        assertEq(address(priv_balance).balance, 0);
        assertEq(alice.balance, 0);
        assertEq(bob.balance, amount);

        assertEq(priv_balance.getActionQueueSize(), 1);
    }
}
