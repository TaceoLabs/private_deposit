pub(crate) mod hash;

// The code limits transaction amounts to u64, which should be sufficient for most use cases. This is required for range checks and >= operations.

// A read should return the balance and the randomness to the user, such that the user can verify the commitment on chain. The read operation does not necessarily require a ZK proof, since the relevant data can be recomputed by the user if it gets the shares directly.
// TODO we may want to extend this function with encryption of the shares to the user, so that the user can receive the data via the smart contract
pub fn read(balance: Field, r: Field) -> Field {
    hash::commit1(balance, r)
}

// A deposit adds an amount to the existing balance and computes a new commitment with a new randomness. Both, the old commitment and the new commitment need to go on chain, such that the proof can be verified.
pub fn deposit(old_balance: Field, old_r: Field, amount: Field, new_r: Field) -> (Field, Field) {
    amount.assert_max_bit_size::<64>();
    deposit_inner(old_balance, old_r, amount, new_r)
}

// Deposit without the range check on amount
fn deposit_inner(old_balance: Field, old_r: Field, amount: Field, new_r: Field) -> (Field, Field) {
    let new_balance = old_balance + amount;
    let old_commitment = hash::commit1(old_balance, old_r);
    let new_commitment = hash::commit1(new_balance, new_r);
    (old_commitment, new_commitment)
}

// A withdraw deducts an amount from the existing balance and computes a new commitment with a new randomness. Both, the old commitment and the new commitment need to go on chain, such that the proof can be verified.
// In order to prevent negative balances, the proof needs to show that new_balance >= 0, which we show by limiting the new balance to 64 bits.
pub fn withdraw(
    old_balance: Field,
    old_r: Field,
    amount: Field,
    new_r: Field,
) -> (Field, Field) {
    amount.assert_max_bit_size::<64>();
    withdraw_inner(old_balance, old_r, amount, new_r)
}

// Withdraw without the range check on amount
fn withdraw_inner( old_balance: Field,
    old_r: Field,
    amount: Field,
    new_r: Field,
) -> (Field, Field) {
    let new_balance = old_balance - amount;
    new_balance.assert_max_bit_size::<64>();
    let old_commitment = hash::commit1(old_balance, old_r);
    let new_commitment = hash::commit1(new_balance, new_r);
    (old_commitment, new_commitment)
}

// Deposits amount to receiver and withdraws amount from sender
pub fn transaction(
    sender_old_balance: Field,
    sender_old_r: Field,
    receiver_old_balance: Field,
    receiver_old_r: Field,
    amount: Field,
    sender_new_r: Field,
    receiver_new_r: Field,
) -> (Field, Field, Field, Field) {
    amount.assert_max_bit_size::<64>();
    let (sender_old_commitment, sender_new_commitment) =
        withdraw_inner(sender_old_balance, sender_old_r, amount, sender_new_r);
    let (receiver_old_commitment, receiver_new_commitment) =
        deposit_inner(receiver_old_balance, receiver_old_r, amount, receiver_new_r);
    (sender_old_commitment, sender_new_commitment, receiver_old_commitment, receiver_new_commitment)
}
