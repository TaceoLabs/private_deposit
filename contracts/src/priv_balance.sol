// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/console.sol";
import {Poseidon2T2} from "./poseidon2.sol";
import {Action, ActionQuery, QueryMap, QueryMapLib, Iterator} from "./action_queue.sol";

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

    // MPC public keys
    BabyJubJubElement public mpc_pk1;
    BabyJubJubElement public mpc_pk2;
    BabyJubJubElement public mpc_pk3;

    // Stores the commitments to the balances of users
    mapping(address => uint256) public balanceCommitments;

    // Stores the actions which are not yet processed
    QueryMap public action_queue;

    // Stores the secret shares of the amount and randomness for a transfer
    mapping(uint256 => Ciphertext) private shares;

    // Batch size for processing actions
    uint private constant BATCH_SIZE = 96;
    // Commitment to zero balance commit(0, 0)
    uint private constant ZERO_COMMITMENT =
        0x87f763a403ee4109adc79d4a7638af3cb8cb6a33f5b027bd1476ffa97361acb;

    // BabyJubJub curve parameters
    uint256 public constant A = 168700;
    uint256 public constant D = 168696;

    // The error codes
    error Unauthorized();
    error InvalidProof();
    error InvalidMpcAction();
    error NotInPrimeField();
    error InvalidAmount();
    error InvalidTransfer();
    error CannotRemoveDummyAction();
    error InvalidCommitment();
    error NotOnCurve();

    modifier onlyMPC() {
        if (msg.sender != mpcAdress) revert Unauthorized();
        _;
    }

    constructor(
        address _verifierAddress,
        address _mpcAdress,
        BabyJubJubElement memory _mpc_pk1,
        BabyJubJubElement memory _mpc_pk2,
        BabyJubJubElement memory _mpc_pk3
    ) {
        mpc_pk1 = _mpc_pk1;
        mpc_pk2 = _mpc_pk2;
        mpc_pk3 = _mpc_pk3;

        if (!isOnBabyJubJubCurve(_mpc_pk1.x, _mpc_pk1.y)) {
            revert NotOnCurve();
        }
        if (!isOnBabyJubJubCurve(_mpc_pk2.x, _mpc_pk2.y)) {
            revert NotOnCurve();
        }
        if (!isOnBabyJubJubCurve(_mpc_pk3.x, _mpc_pk3.y)) {
            revert NotOnCurve();
        }

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

    struct BabyJubJubElement {
        uint256 x;
        uint256 y;
    }

    // We do not store a nonce, since we assume that the sender_pk is randomly sampled each time
    struct Ciphertext {
        uint256[3] amount;
        uint256[3] r;
        BabyJubJubElement sender_pk;
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

    function getCiphertextAtIndex(
        uint256 index
    ) public view returns (Ciphertext memory) {
        return shares[index];
    }

    function commit(
        uint256 input,
        uint256 randomness
    ) public pure returns (uint256) {
        if (input >= Poseidon2T2.PRIME) {
            revert NotInPrimeField();
        }
        if (randomness >= Poseidon2T2.PRIME) {
            revert NotInPrimeField();
        }
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
        // This is at most 2^80 / 10^18 = 1_208_925.8 ETH
        if (amount > 0xFFFFFFFFFFFFFFFFFFFF) {
            revert InvalidAmount();
        }
        if (amount == 0) {
            revert InvalidAmount();
        }

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
        // This is at most 2^80 / 10^18 = 1_208_925.8 ETH
        if (amount > 0xFFFFFFFFFFFFFFFFFFFF) {
            revert InvalidAmount();
        }
        if (amount == 0) {
            revert InvalidAmount();
        }
        // We do not check if the sender has a balance here, because it might be topped up by an action in the queue

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
        uint256 amount,
        Ciphertext calldata ciphertext
    ) public returns (uint256) {
        address sender = msg.sender;
        // Amount is just a commitment here
        if (amount >= Poseidon2T2.PRIME) {
            revert NotInPrimeField();
        }
        if (sender == receiver) {
            revert InvalidTransfer();
        }
        // We do not check if the sender has a balance here, because it might be topped up by an action in the queue

        if (
            !isOnBabyJubJubCurve(ciphertext.sender_pk.x, ciphertext.sender_pk.y)
        ) {
            revert NotOnCurve();
        }

        if (ciphertext.amount[0] >= Poseidon2T2.PRIME) revert NotInPrimeField();
        if (ciphertext.amount[1] >= Poseidon2T2.PRIME) revert NotInPrimeField();
        if (ciphertext.amount[2] >= Poseidon2T2.PRIME) revert NotInPrimeField();
        if (ciphertext.r[0] >= Poseidon2T2.PRIME) revert NotInPrimeField();
        if (ciphertext.r[1] >= Poseidon2T2.PRIME) revert NotInPrimeField();
        if (ciphertext.r[2] >= Poseidon2T2.PRIME) revert NotInPrimeField();

        ActionQuery memory aq = ActionQuery(
            Action.Transfer,
            sender,
            receiver,
            amount
        );
        uint256 index = getNextFreeQueueIndex();
        action_queue.insert(index, aq);
        shares[index] = ciphertext;
        return index;
    }

    // This is in case of the MPC network knowing that an action is faulty.
    // TODO do we need a ZK proof that the action is indeed faulty?
    function removeActionAtIndex(uint256 index) public onlyMPC {
        // We are not allowed to remove 0
        if (index == 0) revert CannotRemoveDummyAction();
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

            // We do not check the input commitments to be in the prime field, as this is done in the ZK proof verification

            if (aq.action == Action.Deposit) {
                uint256 receiver_old_commitment = getBalanceCommitment(
                    aq.receiver
                );
                if (inputs.commitments[i * 2] != 0) {
                    revert InvalidCommitment();
                }

                // compute amount commitment
                uint256 amount_commitment = commit(amount, 0);

                // Update the commitments on-chain
                balanceCommitments[aq.receiver] = inputs.commitments[i * 2 + 1];

                // Fill the commitments array for ZK proof verification
                commitments[i * 5] = amount_commitment; // sender_old_commitment
                commitments[i * 5 + 1] = ZERO_COMMITMENT; // sender_new_commitment
                commitments[i * 5 + 2] = receiver_old_commitment;
                commitments[i * 5 + 3] = inputs.commitments[i * 2 + 1]; // receiver_new_commitment
                commitments[i * 5 + 4] = amount_commitment;

                // Remove the action from the queue
                action_queue.remove(index);
            } else if (aq.action == Action.Withdraw) {
                uint256 sender_old_commitment = getBalanceCommitment(aq.sender);
                if (inputs.commitments[i * 2 + 1] != 0) {
                    revert InvalidCommitment();
                }

                // compute amount commitment
                uint256 amount_commitment = commit(amount, 0);

                // Update the commitments on-chain
                balanceCommitments[aq.sender] = inputs.commitments[i * 2];

                // Fill the commitments array for ZK proof verification
                commitments[i * 5] = sender_old_commitment;
                commitments[i * 5 + 1] = inputs.commitments[i * 2]; // sender_new_commitment
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
                balanceCommitments[aq.sender] = inputs.commitments[i * 2];
                balanceCommitments[aq.receiver] = inputs.commitments[i * 2 + 1];

                // Fill the commitments array for ZK proof verification
                commitments[i * 5] = sender_old_commitment;
                commitments[i * 5 + 1] = inputs.commitments[i * 2]; // sender_new_commitment
                commitments[i * 5 + 2] = receiver_old_commitment;
                commitments[i * 5 + 3] = inputs.commitments[i * 2 + 1]; // receiver_new_commitment
                commitments[i * 5 + 4] = amount; // Is already a commitment

                // Remove the action from the queue
                action_queue.remove(index);
                delete shares[index];
            } else if (aq.action == Action.Dummy) {
                // Do nothing, just add zeros to the commitments
                if (inputs.commitments[i * 2] != 0) {
                    revert InvalidCommitment();
                }
                if (inputs.commitments[i * 2 + 1] != 0) {
                    revert InvalidCommitment();
                }
                commitments[i * 5] = ZERO_COMMITMENT;
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

    function read_queue()
        public
        view
        returns (uint256[] memory, ActionQuery[] memory)
    {
        uint256 size = action_queue.map_size() - 1; // Exclude dummy
        if (size > BATCH_SIZE) {
            size = BATCH_SIZE;
        }
        ActionQuery[] memory actions = new ActionQuery[](size);
        uint256[] memory keys = new uint256[](size);

        Iterator it = action_queue.iterateStart();
        for (uint256 i = 0; i < size; i++) {
            it = action_queue.iterateNext(it); // Doing it here already skips dummy at index 0
            (keys[i], actions[i]) = action_queue.iterateGet(it);
        }
        return (keys, actions);
    }

    // Check if point is on curve: a*x^2 + y^2 = 1 + d*x^2*y^2
    function isOnBabyJubJubCurve(
        uint256 x,
        uint256 y
    ) public pure returns (bool) {
        if (x == 0 && y == 1) return true;
        if (x >= Poseidon2T2.PRIME || y >= Poseidon2T2.PRIME) return false;

        uint256 xx = mulmod(x, x, Poseidon2T2.PRIME);
        uint256 yy = mulmod(y, y, Poseidon2T2.PRIME);
        uint256 axx = mulmod(A, xx, Poseidon2T2.PRIME);
        uint256 dxxyy = mulmod(
            D,
            mulmod(xx, yy, Poseidon2T2.PRIME),
            Poseidon2T2.PRIME
        );

        return
            addmod(axx, yy, Poseidon2T2.PRIME) ==
            addmod(1, dxxyy, Poseidon2T2.PRIME);
    }
}
