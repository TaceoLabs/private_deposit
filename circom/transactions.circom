pragma circom 2.2.2;

include "circomlib/bitify.circom";
include "poseidon2/poseidon2.circom";

template Commit1() {
    signal input value;
    signal input r;
    signal output c;

    var DS = 0xDEADBEEF;
    var state[2] = Poseidon2(2)([value + DS, r]);
    c <== state[0] + value;
}

template CheckAmount() {
    signal input amount;
    signal input amount_r;
    signal output amount_c;

    var NUM_AMOUNT_BITS = 64;

    var bits[NUM_AMOUNT_BITS] = Num2Bits(NUM_AMOUNT_BITS)(amount);
    var commitment = Commit1()(amount, amount_r);
    amount_c <== commitment;
}

template DepositInner() {
    signal input old_balance;
    signal input old_r;
    signal input amount;
    signal input new_r;
    signal output old_c;
    signal output new_c;

    signal new_balance <== old_balance + amount;
    var old_commitment = Commit1()(old_balance, old_r);
    var new_commitment = Commit1()(new_balance, new_r);
    old_c <== old_commitment;
    new_c <== new_commitment;
}

template Deposit() {
    signal input old_balance;
    signal input old_r;
    signal input amount;
    signal input amount_r;
    signal input new_r;
    signal output old_c;
    signal output new_c;
    signal output amount_c;

    var amount_commitment = CheckAmount()(amount, amount_r);
    amount_c <== amount_commitment;

    component deposit = DepositInner();
    deposit.old_balance <== old_balance;
    deposit.old_r <== old_r;
    deposit.amount <== amount;
    deposit.new_r <== new_r;
    old_c <== deposit.old_c;
    new_c <== deposit.new_c;
}

template WithdrawInner() {
    signal input old_balance;
    signal input old_r;
    signal input amount;
    signal input new_r;
    signal output old_c;
    signal output new_c;

    var NUM_WITHDRAW_NEW_BITS = 100;

    signal new_balance <== old_balance - amount;
    var bits[NUM_WITHDRAW_NEW_BITS] = Num2Bits(NUM_WITHDRAW_NEW_BITS)(new_balance);
    var old_commitment = Commit1()(old_balance, old_r);
    var new_commitment = Commit1()(new_balance, new_r);
    old_c <== old_commitment;
    new_c <== new_commitment;
}

template Withdraw() {
    signal input old_balance;
    signal input old_r;
    signal input amount;
    signal input amount_r;
    signal input new_r;
    signal output old_c;
    signal output new_c;
    signal output amount_c;

    var amount_commitment = CheckAmount()(amount, amount_r);
    amount_c <== amount_commitment;

    component withdraw = WithdrawInner();
    withdraw.old_balance <== old_balance;
    withdraw.old_r <== old_r;
    withdraw.amount <== amount;
    withdraw.new_r <== new_r;
    old_c <== withdraw.old_c;
    new_c <== withdraw.new_c;
}

template Transaction() {
    signal input sender_old_balance;
    signal input sender_old_r;
    signal input receiver_old_balance;
    signal input receiver_old_r;
    signal input amount;
    signal input amount_r;
    signal input sender_new_r;
    signal input receiver_new_r;
    signal output sender_old_c;
    signal output sender_new_c;
    signal output receiver_old_c;
    signal output receiver_new_c;
    signal output amount_c;

    var amount_commitment = CheckAmount()(amount, amount_r);
    amount_c <== amount_commitment;

    component withdraw = WithdrawInner();
    withdraw.old_balance <== sender_old_balance;
    withdraw.old_r <== sender_old_r;
    withdraw.amount <== amount;
    withdraw.new_r <== sender_new_r;
    sender_old_c <== withdraw.old_c;
    sender_new_c <== withdraw.new_c;

    component deposit = DepositInner();
    deposit.old_balance <== receiver_old_balance;
    deposit.old_r <== receiver_old_r;
    deposit.amount <== amount;
    deposit.new_r <== receiver_new_r;
    receiver_old_c <== deposit.old_c;
    receiver_new_c <== deposit.new_c;
}

bus TransactionInput {
    signal sender_old_balance;
    signal sender_old_r;
    signal receiver_old_balance;
    signal receiver_old_r;
    signal amount;
    signal amount_r;
    signal sender_new_r;
    signal receiver_new_r;
}

bus TransactionOutput {
    signal sender_old_commitment;
    signal sender_new_commitment;
    signal receiver_old_commitment;
    signal receiver_new_commitment;
    signal amount_commitment;
}

template TransactionBatched(N) {
    input TransactionInput() in[N];
    output TransactionOutput() out[N];

    component transactions[N];
    for (var i=0; i<N; i++) {
        transactions[i] = Transaction();
        transactions[i].sender_old_balance <== in[i].sender_old_balance;
        transactions[i].sender_old_r <== in[i].sender_old_r;
        transactions[i].receiver_old_balance <== in[i].receiver_old_balance;
        transactions[i].receiver_old_r <== in[i].receiver_old_r;
        transactions[i].amount <== in[i].amount;
        transactions[i].amount_r <== in[i].amount_r;
        transactions[i].sender_new_r <== in[i].sender_new_r;
        transactions[i].receiver_new_r <== in[i].receiver_new_r;

        out[i].sender_old_commitment <== transactions[i].sender_old_c;
        out[i].sender_new_commitment <== transactions[i].sender_new_c;
        out[i].receiver_old_commitment <== transactions[i].receiver_old_c;
        out[i].receiver_new_commitment <== transactions[i].receiver_new_c;
        out[i].amount_commitment <== transactions[i].amount_c;
    }
}
