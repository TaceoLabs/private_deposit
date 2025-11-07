// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

enum Action {
    Invalid, // Returned when querying a non-existing action
    Deposit,
    Withdraw,
    Transfer,
    Dummy // Placeholder to fill batches
}

struct ActionQuery {
    Action action;
    address sender;
    address receiver;
    uint256 amount; // Either a commitment or an actual amount
}

struct IndexValue {
    bool present;
    ActionQuery value;
}

struct QueryMap {
    IndexValue[] data;
    uint256 lowestKey;
    uint256 size;
}

library QueryMapLib {
    function push(QueryMap storage self, ActionQuery memory value) public {
        self.data.push(IndexValue(true, value));
        self.size++;
    }

    function get(
        QueryMap storage self,
        uint256 key
    ) public view returns (ActionQuery memory value) {
        if (!self.data[key].present) {
            return ActionQuery(Action.Invalid, address(0), address(0), 0);
        }
        return self.data[key].value;
    }

    function map_size(QueryMap storage self) public view returns (uint256) {
        return self.size;
    }

    function highest_key(QueryMap storage self) public view returns (uint256) {
        return self.data.length - 1;
    }

    function remove(
        QueryMap storage self,
        uint256 key
    ) public returns (bool success) {
        if (key >= self.data.length || !self.data[key].present) {
            return false;
        }
        delete self.data[key];
        self.size--;
        if (key == self.lowestKey) {
            // Update lowestKey
            while (
                self.lowestKey < self.data.length &&
                !self.data[self.lowestKey].present
            ) {
                self.lowestKey++;
            }
        }
        return true;
    }

    function next_key(
        QueryMap storage self,
        uint256 currentKey
    ) public view returns (uint256, bool) {
        uint256 nextKey = currentKey + 1;
        while (nextKey < self.data.length && !self.data[nextKey].present) {
            nextKey++;
        }
        if (nextKey >= self.data.length) {
            return (0, false);
        }
        return (nextKey, true);
    }

    function contains(
        QueryMap storage self,
        uint256 key
    ) public view returns (bool) {
        return self.data[key].present;
    }
}

///////////////////////////////////////////////////////////////////////////////
