// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockClientVerifier {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[15] calldata
    ) external pure returns (bool) {
        return true;
    }
}
