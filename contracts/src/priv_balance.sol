// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// import "forge-std/console.sol";
// import {Action, ActionQuery, QueryMap, QueryMapLib, Iterator} from "./action_queue.sol";
import {Action, ActionQuery, QueryMap, QueryMapLib} from "./action_vector.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

interface IGroth16Verifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[250] calldata _pubSignals
    ) external view returns (bool);
}

interface Poseidon2T2_BN254 {
    function compress(uint256[2] memory inputs, uint256 domain_sep) external pure returns (uint256);
}

contract PrivateBalance {
    using QueryMapLib for QueryMap;
    using SafeERC20 for IERC20;

    // The groth16 verifier contract
    IGroth16Verifier public immutable verifier;
    // The poseidon2 contract
    Poseidon2T2_BN254 public immutable poseidon2;
    // The token we use
    IERC20 public immutable token;

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

    // For the demo we only allow a list of certain addresses to interact with the contract. We can however also instantiate it to allow everyone using the allow_all flag.
    mapping(address => bool) public demo_whitelist;
    bool allow_all;

    // BN254 prime field
    uint256 constant PRIME = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    // Batch size for processing actions
    uint256 private constant BATCH_SIZE = 50;
    // Commitment to zero balance commit(0, 0)
    uint256 private constant ZERO_COMMITMENT = 0x87f763a403ee4109adc79d4a7638af3cb8cb6a33f5b027bd1476ffa97361acb;

    uint256 private constant DS = 0xDEADBEEF;

    // BabyJubJub curve parameters
    uint256 public constant A = 168700;
    uint256 public constant D = 168696;

    // We emit the location of the registered action indices for deposit, withdraw, and transfer
    event Deposit(uint256 action_index);
    event Withdraw(uint256 action_index);
    event Transfer(uint256 action_index);
    event TransferBatch(uint256[] action_indices);

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
    error InvalidParameters();

    modifier onlyMPC() {
        if (msg.sender != mpcAdress) revert Unauthorized();
        _;
    }

    modifier demoWhitelist() {
        if (!allow_all) {
            if (!demo_whitelist[msg.sender]) {
                revert Unauthorized();
            }
        }
        _;
    }

    constructor(
        address _verifierAddress,
        address _poseidon2Address,
        address _tokenAddress,
        address _mpcAdress,
        BabyJubJubElement memory _mpc_pk1,
        BabyJubJubElement memory _mpc_pk2,
        BabyJubJubElement memory _mpc_pk3,
        bool _allow_all
    ) {
        mpc_pk1 = _mpc_pk1;
        mpc_pk2 = _mpc_pk2;
        mpc_pk3 = _mpc_pk3;
        allow_all = _allow_all;

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
        poseidon2 = Poseidon2T2_BN254(_poseidon2Address);
        token = IERC20(_tokenAddress);
        mpcAdress = _mpcAdress;
        ActionQuery memory aq = ActionQuery(Action.Dummy, address(0), address(0), 0);
        action_queue.push(aq); // Dummy action at index 0
        action_queue.lowestKey = 1; // We skip the dummy in the iterator
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

    function whitelistForDemo(address[] calldata addresses) public onlyMPC {
        for (uint256 i = 0; i < addresses.length; i++) {
            demo_whitelist[addresses[i]] = true;
        }
    }

    // This initializes the mapping for demo purposes so that we do not need to deposit for each user. This simplifies the demo setup such that we do not need to give each wallet some funds to call deposit().
    // It is intended that during this function call the setup party of the demo deposits enough funds to the contract to back these balances.
    function setBalancesForDemo(address[] calldata addresses, uint256[] calldata commitments, uint256 total_balance)
        public
        onlyMPC
    {
        if (addresses.length != commitments.length) {
            revert InvalidParameters();
        }

        for (uint256 i = 0; i < addresses.length; i++) {
            if (commitments[i] >= PRIME) {
                revert NotInPrimeField();
            }
            balanceCommitments[addresses[i]] = commitments[i];
        }
        token.safeTransferFrom(msg.sender, address(this), total_balance);
    }

    function getBalanceCommitment(address user) public view returns (uint256) {
        uint256 commitment = balanceCommitments[user];
        if (commitment == 0) {
            // Commitment is never zero with overwhelming probability
            return ZERO_COMMITMENT;
        }
        return commitment;
    }

    function getActionAtIndex(uint256 index) public view returns (ActionQuery memory) {
        return action_queue.get(index);
    }

    function getActionQueueSize() public view returns (uint256) {
        return action_queue.map_size();
    }

    function getCiphertextAtIndex(uint256 index) public view returns (Ciphertext memory) {
        return shares[index];
    }

    function commit(uint256 input, uint256 randomness) public view returns (uint256) {
        if (input >= PRIME) {
            revert NotInPrimeField();
        }
        if (randomness >= PRIME) {
            revert NotInPrimeField();
        }
        return poseidon2.compress([input, randomness], DS);
    }

    // TODO the following is just for a demo to be able to retrieve funds after it is done
    // Remove for a real deployment
    function retrieveFunds(address receiver) public onlyMPC {
        token.safeTransfer(receiver, token.balanceOf(address(this)));
    }

    function deposit(uint256 amount) public demoWhitelist returns (uint256) {
        address receiver = msg.sender;
        // This is at most 2^80 / 10^18 = 1_208_925.8 ETH
        if (amount > 0xFFFFFFFFFFFFFFFFFFFF) {
            revert InvalidAmount();
        }
        if (amount == 0) {
            revert InvalidAmount();
        }

        ActionQuery memory aq = ActionQuery(Action.Deposit, address(0), receiver, amount);
        action_queue.push(aq);

        token.safeTransferFrom(receiver, address(this), amount);
        uint256 index = action_queue.highest_key();
        emit Deposit(index);
        return index;
    }

    function withdraw(uint256 amount) public demoWhitelist returns (uint256) {
        address sender = msg.sender;
        // This is at most 2^80 / 10^18 = 1_208_925.8 ETH
        if (amount > 0xFFFFFFFFFFFFFFFFFFFF) {
            revert InvalidAmount();
        }
        if (amount == 0) {
            revert InvalidAmount();
        }
        // We do not check if the sender has a balance here, because it might be topped up by an action in the queue

        ActionQuery memory aq = ActionQuery(Action.Withdraw, sender, address(0), amount);
        action_queue.push(aq);
        uint256 index = action_queue.highest_key();
        emit Withdraw(index);
        return index;
    }

    function transfer(address receiver, uint256 amount, Ciphertext calldata ciphertext)
        public
        demoWhitelist
        returns (uint256)
    {
        address sender = msg.sender;
        // Amount is just a commitment here
        if (amount >= PRIME) {
            revert NotInPrimeField();
        }
        if (sender == receiver) {
            revert InvalidTransfer();
        }
        // We do not check if the sender has a balance here, because it might be topped up by an action in the queue

        if (!isOnBabyJubJubCurve(ciphertext.sender_pk.x, ciphertext.sender_pk.y)) {
            revert NotOnCurve();
        }

        if (ciphertext.amount[0] >= PRIME) revert NotInPrimeField();
        if (ciphertext.amount[1] >= PRIME) revert NotInPrimeField();
        if (ciphertext.amount[2] >= PRIME) revert NotInPrimeField();
        if (ciphertext.r[0] >= PRIME) revert NotInPrimeField();
        if (ciphertext.r[1] >= PRIME) revert NotInPrimeField();
        if (ciphertext.r[2] >= PRIME) revert NotInPrimeField();

        ActionQuery memory aq = ActionQuery(Action.Transfer, sender, receiver, amount);

        action_queue.push(aq);
        uint256 index = action_queue.highest_key();
        shares[index] = ciphertext;
        emit Transfer(index);
        return index;
    }

    // TODO This function is only used for demo to make it easier to register transactions (we do not need to fund a lot of different wallets to pay the gas costs). It does not check a signature of the sender_pk and the ciphertexts are assumed to be given to the MPC network off-chain.
    function transferBatch(
        address[] calldata senders,
        address[] calldata receivers,
        uint256[] calldata amount_commitments
        // Ciphertext[] calldata ciphertexts
    ) public onlyMPC returns (uint256[] memory) {
        if (
            senders.length != receivers.length || receivers.length != amount_commitments.length
            // || receivers.length != ciphertexts.length
        ) {
            revert InvalidParameters();
        }
        uint256[] memory indices = new uint256[](receivers.length);
        for (uint256 i = 0; i < receivers.length; i++) {
            address sender = senders[i];
            address receiver = receivers[i];
            uint256 amount = amount_commitments[i];
            // Amount is just a commitment here
            if (amount >= PRIME) {
                revert NotInPrimeField();
            }
            if (sender == receiver) {
                revert InvalidTransfer();
            }
            // We do not check if the sender has a balance here, because it might be topped up by an action in the queue

            // if (!isOnBabyJubJubCurve(ciphertexts[i].sender_pk.x, ciphertexts[i].sender_pk.y)) {
            //     revert NotOnCurve();
            // }

            // if (ciphertexts[i].amount[0] >= PRIME) revert NotInPrimeField();
            // if (ciphertexts[i].amount[1] >= PRIME) revert NotInPrimeField();
            // if (ciphertexts[i].amount[2] >= PRIME) revert NotInPrimeField();
            // if (ciphertexts[i].r[0] >= PRIME) revert NotInPrimeField();
            // if (ciphertexts[i].r[1] >= PRIME) revert NotInPrimeField();
            // if (ciphertexts[i].r[2] >= PRIME) revert NotInPrimeField();

            ActionQuery memory aq = ActionQuery(Action.Transfer, sender, receiver, amount);
            action_queue.push(aq);
            uint256 index = action_queue.highest_key();
            // shares[index] = ciphertexts[i];
            indices[i] = index;
        }
        emit TransferBatch(indices);
        return indices;
    }

    // TODO This is in case of the MPC network knowing that an action is faulty and is just here for a demo (in case something gets wrong). In a real deployment this function should either not be included, or take a ZK proof that the action is indeed invalid.
    function removeActionAtIndex(uint256 index) public onlyMPC {
        // We are not allowed to remove 0
        if (index == 0) revert CannotRemoveDummyAction();
        action_queue.remove(index);
    }

    // TODO This function is only for demo purposes to be able to clear the action queue in case something goes wrong. In a real deployment this function should not be included.
    function removeAllOpenActions() public onlyMPC {
        uint256 num_items = action_queue.size - 1; // Exclude dummy
        uint256 it = action_queue.lowestKey;
        for (uint256 i = 0; i < num_items; i++) {
            action_queue.remove(it);
            it = action_queue.lowestKey;
        }
    }

    // This function processes a batch of actions, updates the commitments,
    // and removes the actions from the queue.
    // Deposit and Withdraw are rewritten to be transfers
    function processMPC(TransactionInput calldata inputs, Groth16Proof calldata proof) public onlyMPC {
        uint256[BATCH_SIZE * 5] memory commitments;

        for (uint256 i = 0; i < BATCH_SIZE; i++) {
            uint256 index = inputs.action_index[i];
            ActionQuery memory aq = action_queue.get(index);
            uint256 amount = aq.amount;

            // We do not check the input commitments to be in the prime field, as this is done in the ZK proof verification

            if (aq.action == Action.Deposit) {
                uint256 receiver_old_commitment = getBalanceCommitment(aq.receiver);
                if (inputs.commitments[i * 2] != 0) {
                    revert InvalidCommitment();
                }

                // compute amount commitment
                uint256 amount_commitment = poseidon2.compress([amount, 0], DS);

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
                uint256 sender_old_commitment = balanceCommitments[aq.sender];
                if (inputs.commitments[i * 2 + 1] != 0) {
                    revert InvalidCommitment();
                }

                // compute amount commitment
                uint256 amount_commitment = poseidon2.compress([amount, 0], DS);

                // Update the commitments on-chain
                balanceCommitments[aq.sender] = inputs.commitments[i * 2];

                // Fill the commitments array for ZK proof verification
                commitments[i * 5] = sender_old_commitment;
                commitments[i * 5 + 1] = inputs.commitments[i * 2]; // sender_new_commitment
                commitments[i * 5 + 2] = ZERO_COMMITMENT; // receiver_old_commitment
                commitments[i * 5 + 3] = amount_commitment; // receiver_new_commitment
                commitments[i * 5 + 4] = amount_commitment;

                // Send the actual tokens
                token.safeTransfer(aq.sender, amount);

                // Remove the action from the queue
                action_queue.remove(index);
            } else if (aq.action == Action.Transfer) {
                uint256 sender_old_commitment = balanceCommitments[aq.sender];
                uint256 receiver_old_commitment = getBalanceCommitment(aq.receiver);

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
                // delete shares[index]; // Actually costs more gas
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

    function read_queue(uint256 num_items)
        public
        view
        returns (uint256[] memory, ActionQuery[] memory, Ciphertext[] memory)
    {
        uint256 size = action_queue.size - 1; // Exclude dummy
        if (num_items > size) {
            num_items = size;
        }
        ActionQuery[] memory actions = new ActionQuery[](num_items);
        uint256[] memory keys = new uint256[](num_items);
        Ciphertext[] memory cts = new Ciphertext[](num_items);

        uint256 it = action_queue.lowestKey;
        for (uint256 i = 0; i < num_items; i++) {
            keys[i] = it;
            actions[i] = action_queue.get(it);
            if (actions[i].action == Action.Transfer) {
                cts[i] = shares[it];
            }
            (it,) = action_queue.next_key(it);
        }
        return (keys, actions, cts);
    }

    // Check if point is on curve: a*x^2 + y^2 = 1 + d*x^2*y^2
    function isOnBabyJubJubCurve(uint256 x, uint256 y) public pure returns (bool) {
        if (x == 0 && y == 1) return true;
        if (x >= PRIME || y >= PRIME) return false;

        uint256 xx = mulmod(x, x, PRIME);
        uint256 yy = mulmod(y, y, PRIME);
        uint256 axx = mulmod(A, xx, PRIME);
        uint256 dxxyy = mulmod(D, mulmod(xx, yy, PRIME), PRIME);

        return addmod(axx, yy, PRIME) == addmod(1, dxxyy, PRIME);
    }
}
