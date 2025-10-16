// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {Iterator, Action, ActionQuery, QueryMap, QueryMapLib} from "../src/action_queue.sol";

contract ActionQueueTest is Test {
    using QueryMapLib for QueryMap;

    QueryMap action_queue;

    function testOrder() public {
        ActionQuery memory aq = ActionQuery(
            Action.Deposit,
            address(0x1),
            address(0x2),
            100
        );

        // Insert keys in non-sorted order
        action_queue.insert(3, aq);
        action_queue.insert(1, aq);

        uint count = 0;
        for (
            Iterator i = action_queue.iterateStart();
            action_queue.iterateValid(i);
            i = action_queue.iterateNext(i)
        ) {
            (uint256 key, ) = action_queue.iterateGet(i);
            console.log("key:", key);
            if (count == 0) {
                assertEq(key, 3);
            } else if (count == 1) {
                assertEq(key, 1);
            } else {
                fail();
            }
            count++;
        }
        console.log("");

        // Remove 3 and check that only 1 remains
        action_queue.remove(3);

        count = 0;
        for (
            Iterator i = action_queue.iterateStart();
            action_queue.iterateValid(i);
            i = action_queue.iterateNext(i)
        ) {
            (uint256 key, ) = action_queue.iterateGet(i);
            console.log("key:", key);
            if (count == 0) {
                assertEq(key, 1);
            } else {
                fail();
            }
            count++;
        }
        console.log("");

        // Insert 3 again and order should be 1,3
        action_queue.insert(3, aq);

        count = 0;
        for (
            Iterator i = action_queue.iterateStart();
            action_queue.iterateValid(i);
            i = action_queue.iterateNext(i)
        ) {
            (uint256 key, ) = action_queue.iterateGet(i);
            console.log("key:", key);
            if (count == 0) {
                assertEq(key, 1);
            } else if (count == 1) {
                assertEq(key, 3);
            } else {
                fail();
            }
            count++;
        }
    }
}
