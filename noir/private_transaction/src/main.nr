// Compile with: nargo compile --expression-width=1000 --bounded-codegen

// Deposits amount to receiver and withdraws amount from sender
pub fn main(
    sender_old_balance: Field,
    sender_old_r: Field,
    receiver_old_balance: Field,
    receiver_old_r: Field,
    amount: Field,
    amount_r: Field,
    sender_new_r: Field,
    receiver_new_r: Field,
) -> pub (Field, Field, Field, Field, Field) {
    private_deposit_common::transaction(
        sender_old_balance,
        sender_old_r,
        receiver_old_balance,
        receiver_old_r,
        amount,
        amount_r,
        sender_new_r,
        receiver_new_r,
    )
}
