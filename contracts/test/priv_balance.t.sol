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
    uint public constant ZERO_COMMITMENT =
        0x87f763a403ee4109adc79d4a7638af3cb8cb6a33f5b027bd1476ffa97361acb;

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
        uint256 alice_deposit_commitment = 20475790747163159281381000988950595602246093971970072724497058220972032546227;
        uint256 alice_transfer_commitment = 6126176460504079633062715978677201116365486814740873723495116048221456856662;
        uint256 bob_transfer_commitment = 18230607131064653285520581983677337516418383194152676962436656129238328701512;
        uint256 bob_withdraw_commitment = 16494418544833044837762941503721329507859376086089739719508496266534645057927;

        // The proof
        PrivateBalance.Groth16Proof memory proof;
        proof.pA = [
            13246410413735152849282242637283598349364814803939744688826852346099018491141,
            17209368019034491520517927951207298405118844599811003918402734302003064713120
        ];
        proof.pB = [
            [
                17074801275934450698441268276838385021796737062826778884920061612102201232288,
                10653532112154339392146345420810463233841376316859930450679425614213974261060
            ],
            [
                21066981415794998869793530176379482690249104337372723805142654332616875663333,
                5142267759864406857572427647374128693361889093387966738012978788331939082610
            ]
        ];
        proof.pC = [
            2034989638202545708029238374922508871761571046634435334803282368590243572189,
            19439035317178272594864076670096258799332839234184888230850426824759865720247
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
        inputs.commitments[0] = ZERO_COMMITMENT;
        inputs.commitments[1] = alice_deposit_commitment;

        // Transfer from Alice to Bob
        inputs.action_index[1] = 2;
        inputs.commitments[2] = alice_transfer_commitment;
        inputs.commitments[3] = bob_transfer_commitment;

        // Withdraw by Bob
        inputs.action_index[2] = 3;
        inputs.commitments[4] = bob_withdraw_commitment;
        inputs.commitments[5] = ZERO_COMMITMENT;

        // Dummies
        for (uint256 i = 3; i < BATCH_SIZE; i++) {
            inputs.action_index[i] = 0;
            inputs.commitments[i * 2] = ZERO_COMMITMENT;
            inputs.commitments[i * 2 + 1] = ZERO_COMMITMENT;
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
