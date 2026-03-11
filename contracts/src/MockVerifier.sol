// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice A mock Groth16 verifier that always returns true.
/// Used for demo deployments where the real MPC prover is not available.
contract MockVerifier {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[250] calldata
    ) external pure returns (bool) {
        return true;
    }
}
