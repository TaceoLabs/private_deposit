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

///////////////////////////////////////////////////////////////////////////////
// From https://docs.soliditylang.org/en/latest/types.html#mapping-types
struct IndexValue {
    uint256 keyIndex;
    ActionQuery value;
}
struct KeyFlag {
    uint256 key;
    bool deleted;
}

struct QueryMap {
    mapping(uint256 => IndexValue) data;
    KeyFlag[] keys;
    uint256 size;
}

type Iterator is uint256;

library QueryMapLib {
    function insert(
        QueryMap storage self,
        uint256 key,
        ActionQuery memory value
    ) public returns (bool replaced) {
        uint256 keyIndex = self.data[key].keyIndex;
        self.data[key].value = value;
        if (keyIndex > 0) return true;
        else {
            keyIndex = self.keys.length;
            self.keys.push();
            self.data[key].keyIndex = keyIndex + 1;
            self.keys[keyIndex].key = key;
            self.size++;
            return false;
        }
    }

    function get(
        QueryMap storage self,
        uint256 key
    ) public view returns (ActionQuery memory value) {
        if (self.data[key].keyIndex == 0) {
            return ActionQuery(Action.Invalid, address(0), address(0), 0);
        }
        return self.data[key].value;
    }

    function map_size(QueryMap storage self) public view returns (uint256) {
        return self.size;
    }

    function remove(
        QueryMap storage self,
        uint256 key
    ) public returns (bool success) {
        uint256 keyIndex = self.data[key].keyIndex;
        if (keyIndex == 0) return false;
        delete self.data[key];
        self.keys[keyIndex - 1].deleted = true;
        self.size--;
    }

    function contains(
        QueryMap storage self,
        uint256 key
    ) public view returns (bool) {
        return self.data[key].keyIndex > 0;
    }

    function iterateStart(
        QueryMap storage self
    ) public view returns (Iterator) {
        return iteratorSkipDeleted(self, 0);
    }

    function iterateValid(
        QueryMap storage self,
        Iterator iterator
    ) public view returns (bool) {
        return Iterator.unwrap(iterator) < self.keys.length;
    }

    function iterateNext(
        QueryMap storage self,
        Iterator iterator
    ) public view returns (Iterator) {
        return iteratorSkipDeleted(self, Iterator.unwrap(iterator) + 1);
    }

    function iterateGet(
        QueryMap storage self,
        Iterator iterator
    ) public view returns (uint256 key, ActionQuery memory value) {
        uint256 keyIndex = Iterator.unwrap(iterator);
        key = self.keys[keyIndex].key;
        value = self.data[key].value;
    }

    function iteratorSkipDeleted(
        QueryMap storage self,
        uint256 keyIndex
    ) private view returns (Iterator) {
        while (keyIndex < self.keys.length && self.keys[keyIndex].deleted)
            keyIndex++;
        return Iterator.wrap(keyIndex);
    }
}

///////////////////////////////////////////////////////////////////////////////
