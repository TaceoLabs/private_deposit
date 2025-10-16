// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {PrivateBalance} from "../src/priv_balance.sol";
import {Action, ActionQuery} from "../src/action_queue.sol";

contract PrivateBalanceTest is Test {
    PrivateBalance public priv_balance;
    //  storage action_queue;

    address mpcAdress = address(0x4);

    function setUp() public {
        priv_balance = new PrivateBalance(mpcAdress);
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
}
