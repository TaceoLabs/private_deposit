// Compile with: nargo compile --expression-width=1000 --bounded-codegen

global NUM_TRANSACTIONS: u32 = 96;

pub struct TransactionInput {
    sender_old_balance: Field,
    sender_old_r: Field,
    receiver_old_balance: Field,
    receiver_old_r: Field,
    amount: Field,
    amount_r: Field,
    sender_new_r: Field,
    receiver_new_r: Field,
}

#[derive(Default)]
pub struct TransactionOutput {
    sender_old_commitment: Field,
    sender_new_commitment: Field,
    receiver_old_commitment: Field,
    receiver_new_commitment: Field,
    amount_commitment: Field,
}

// Deposits amount to receiver and withdraws amount from sender
pub fn main(
    transactions: [TransactionInput; NUM_TRANSACTIONS],
) -> pub [TransactionOutput; NUM_TRANSACTIONS] {
    let mut outputs: [TransactionOutput; NUM_TRANSACTIONS] =
        [TransactionOutput::default(); NUM_TRANSACTIONS];

    for i in 0..NUM_TRANSACTIONS {
        let tx = transactions[i];
        let output = private_deposit_common::transaction(
            tx.sender_old_balance,
            tx.sender_old_r,
            tx.receiver_old_balance,
            tx.receiver_old_r,
            tx.amount,
            tx.amount_r,
            tx.sender_new_r,
            tx.receiver_new_r,
        );
        outputs[i] = TransactionOutput {
            sender_old_commitment: output.0,
            sender_new_commitment: output.1,
            receiver_old_commitment: output.2,
            receiver_new_commitment: output.3,
            amount_commitment: output.4,
        };
    }

    outputs
}
