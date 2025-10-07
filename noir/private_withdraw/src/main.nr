// Compile with: nargo compile --expression-width=1000 --bounded-codegen

// A withdraw deducts an amount from the existing balance and computes a new commitment with a new randomness. All, the old commitment, the new commitment, and a commitment to the amount need to go on chain, such that the proof can be verified.
// In order to prevent negative balances, the proof needs to show that new_balance >= 0, which we show by limiting the new balance to 64 bits.
pub fn main(
    old_balance: Field,
    old_r: Field,
    amount: Field,
    amount_r: Field,
    new_r: Field,
) -> pub (Field, Field, Field) {
    private_deposit_common::withdraw(old_balance, old_r, amount, amount_r, new_r)
}
