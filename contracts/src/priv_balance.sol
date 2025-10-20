// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/console.sol";
import {Poseidon2T2} from "./poseidon2.sol";
import {Action, ActionQuery, QueryMap, QueryMapLib} from "./action_queue.sol";

interface IGroth16Verifier {
    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[480] calldata _pubSignals
    ) external view returns (bool);
}

contract PrivateBalance {
    using QueryMapLib for QueryMap;

    // The groth16 verifier contract
    IGroth16Verifier public immutable verifier;

    // The address of the MPC network allowed to post proofs
    address mpcAdress;

    // Stores the commitments to the balances of users
    mapping(address => uint256) public balanceCommitments;

    // Stores the actions which are not yet processed
    QueryMap public action_queue;

    // Batch size for processing actions
    uint private constant BATCH_SIZE = 96;
    // Commitment to zero balance commit(0, 0)
    uint private constant ZERO_COMMITMENT =
        0x87f763a403ee4109adc79d4a7638af3cb8cb6a33f5b027bd1476ffa97361acb;

    // The error codes
    error Unauthorized();
    error InvalidProof();
    error InvalidMpcAction();

    modifier onlyMPC() {
        if (msg.sender != mpcAdress) revert Unauthorized();
        _;
    }

    constructor(address _verifierAddress, address _mpcAdress) {
        verifier = IGroth16Verifier(_verifierAddress);
        mpcAdress = _mpcAdress;
        ActionQuery memory aq = ActionQuery(
            Action.Dummy,
            address(0),
            address(0),
            0
        );
        action_queue.insert(0, aq); // Dummy action at index 0
    }

    struct Groth16Proof {
        uint256[2] pA;
        uint256[2][2] pB;
        uint256[2] pC;
    }

    struct TransactionInput {
        uint256[BATCH_SIZE] action_index;
        uint256[BATCH_SIZE * 2] commitments; // Consists of new_commitments of sender/receiver balances, remaining commitments are read from smart contract
    }

    function getNextFreeQueueIndex() internal view returns (uint256) {
        uint256 index = 0;
        while (action_queue.contains(index)) {
            index++;
        }
        return index;
    }

    function getBalanceCommitment(address user) public view returns (uint256) {
        uint256 commitment = balanceCommitments[user];
        if (commitment == 0) {
            // Commitment is never zero with overwhelming probability
            return ZERO_COMMITMENT;
        }
        return commitment;
    }

    function getActionAtIndex(
        uint256 index
    ) public view returns (ActionQuery memory) {
        return action_queue.get(index);
    }

    function getActionQueueSize() public view returns (uint256) {
        return action_queue.map_size();
    }

    function commit(
        uint256 input,
        uint256 randomness
    ) public pure returns (uint256) {
        require(input < Poseidon2T2.PRIME, "Input too large");
        require(randomness < Poseidon2T2.PRIME, "Randomness too large");
        return Poseidon2T2.compress([input, randomness]);
    }

    // TODO the following is just for a demo to be able to retrieve funds after it is done
    // Remove for a real deployment
    function retrieveFunds() public payable onlyMPC {
        payable(mpcAdress).transfer(address(this).balance);
    }

    function deposit() public payable returns (uint256) {
        address receiver = msg.sender;
        uint256 amount = msg.value;
        // TODO this is at most 2^64 / 10^18 = 18 ETH
        require(amount <= 0xFFFFFFFFFFFFFFFF, "Amount must be 64 bit at most");
        require(amount > 0, "There must be a deposit of some tokens");

        ActionQuery memory aq = ActionQuery(
            Action.Deposit,
            address(0),
            receiver,
            amount
        );
        uint256 index = getNextFreeQueueIndex();
        action_queue.insert(index, aq);
        return index;
    }

    function withdraw(uint256 amount) public returns (uint256) {
        address sender = msg.sender;
        // TODO this is at most 2^64 / 10^18 = 18 ETH
        require(amount <= 0xFFFFFFFFFFFFFFFF, "Amount must be 64 bit at most");
        require(amount > 0, "There must be a withdrawl of some tokens");
        // TODO the following check is not easy to enforce because there might be a balance added via an action in the queue
        // require(
        //     getBalanceCommitment(sender) != ZERO_COMMITMENT,
        //     "The user should have a balance"
        // );

        ActionQuery memory aq = ActionQuery(
            Action.Withdraw,
            sender,
            address(0),
            amount
        );
        uint256 index = getNextFreeQueueIndex();
        action_queue.insert(index, aq);
        return index;
    }

    function transfer(
        address receiver,
        uint256 amount
    ) public returns (uint256) {
        address sender = msg.sender;
        // Amount is just a commitment here
        require(amount < Poseidon2T2.PRIME, "amount too large");
        require(receiver != sender, "Receiver cannot be sender");
        // TODO the following check is not easy to enforce because there might be a balance added via an action in the queue
        // require(
        //     getBalanceCommitment(sender) != ZERO_COMMITMENT,
        //     "The user should have a balance"
        // );

        ActionQuery memory aq = ActionQuery(
            Action.Transfer,
            sender,
            receiver,
            amount
        );
        uint256 index = getNextFreeQueueIndex();
        action_queue.insert(index, aq);
        return index;
    }

    // This is in case of the MPC network knowing that an action is faulty.
    // TODO do we need a ZK proof that the action is indeed faulty?
    function removeActionAtIndex(uint256 index) public onlyMPC {
        // We are not allowed to remove 0
        require(index != 0, "Cannot remove dummy action at index 0");
        action_queue.remove(index);
    }

    // This function processes a batch of actions, updates the commitments,
    // and removes the actions from the queue.
    // Deposit and Withdraw are rewritten to be transfers
    function processMPC(
        TransactionInput calldata inputs,
        Groth16Proof calldata proof
    ) public payable onlyMPC {
        uint256[BATCH_SIZE * 5] memory commitments;

        for (uint i = 0; i < BATCH_SIZE; i++) {
            uint256 index = inputs.action_index[i];
            ActionQuery memory aq = action_queue.get(index);
            uint256 amount = aq.amount;

            if (aq.action == Action.Deposit) {
                uint256 receiver_old_commitment = getBalanceCommitment(
                    aq.receiver
                );
                require(
                    inputs.commitments[i * 2 + 0] == ZERO_COMMITMENT,
                    "Invalid sender commitment for deposit"
                );

                // compute amount commitment
                uint256 amount_commitment = commit(amount, 0);

                // Update the commitments on-chain
                balanceCommitments[aq.receiver] = inputs.commitments[i * 2 + 1];

                // Fill the commitments array for ZK proof verification
                commitments[i * 5 + 0] = amount_commitment; // sender_old_commitment
                commitments[i * 5 + 1] = ZERO_COMMITMENT; // sender_new_commitment
                commitments[i * 5 + 2] = receiver_old_commitment;
                commitments[i * 5 + 3] = inputs.commitments[i * 2 + 1]; // receiver_new_commitment
                commitments[i * 5 + 4] = amount_commitment;

                // Remove the action from the queue
                action_queue.remove(index);
            } else if (aq.action == Action.Withdraw) {
                uint256 sender_old_commitment = getBalanceCommitment(aq.sender);
                require(
                    inputs.commitments[i * 2 + 1] == ZERO_COMMITMENT,
                    "Invalid receiver commitment for withdraw"
                );

                // compute amount commitment
                uint256 amount_commitment = commit(amount, 0);

                // Update the commitments on-chain
                balanceCommitments[aq.sender] = inputs.commitments[i * 2 + 0];

                // Fill the commitments array for ZK proof verification
                commitments[i * 5 + 0] = sender_old_commitment;
                commitments[i * 5 + 1] = inputs.commitments[i * 2 + 0]; // sender_new_commitment
                commitments[i * 5 + 2] = ZERO_COMMITMENT; // receiver_old_commitment
                commitments[i * 5 + 3] = amount_commitment; // receiver_new_commitment
                commitments[i * 5 + 4] = amount_commitment;

                // Send the actual tokens
                payable(aq.sender).transfer(amount);

                // Remove the action from the queue
                action_queue.remove(index);
            } else if (aq.action == Action.Transfer) {
                uint256 sender_old_commitment = getBalanceCommitment(aq.sender);
                uint256 receiver_old_commitment = getBalanceCommitment(
                    aq.receiver
                );

                // Update the commitments on-chain
                balanceCommitments[aq.sender] = inputs.commitments[i * 2 + 0];
                balanceCommitments[aq.receiver] = inputs.commitments[i * 2 + 1];

                // Fill the commitments array for ZK proof verification
                commitments[i * 5 + 0] = sender_old_commitment;
                commitments[i * 5 + 1] = inputs.commitments[i * 2 + 0]; // sender_new_commitment
                commitments[i * 5 + 2] = receiver_old_commitment;
                commitments[i * 5 + 3] = inputs.commitments[i * 2 + 1]; // receiver_new_commitment
                commitments[i * 5 + 4] = amount; // Is already a commitment

                // Remove the action from the queue
                action_queue.remove(index);
            } else if (aq.action == Action.Dummy) {
                // Do nothing, just add zeros to the commitments
                require(
                    inputs.commitments[i * 2 + 0] == ZERO_COMMITMENT,
                    "Invalid sender commitment for dummy"
                );
                require(
                    inputs.commitments[i * 2 + 1] == ZERO_COMMITMENT,
                    "Invalid receiver commitment for dummy"
                );
                commitments[i * 5 + 0] = ZERO_COMMITMENT;
                commitments[i * 5 + 1] = ZERO_COMMITMENT;
                commitments[i * 5 + 2] = ZERO_COMMITMENT;
                commitments[i * 5 + 3] = ZERO_COMMITMENT;
                commitments[i * 5 + 4] = ZERO_COMMITMENT;

                // We do not remove it from the queue
            } else {
                revert InvalidMpcAction();
            }
        }

        if (!verifier.verifyProof(proof.pA, proof.pB, proof.pC, commitments)) {
            revert InvalidProof();
        }
    }
}
