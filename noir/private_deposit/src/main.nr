// Compile with: nargo compile --expression-width=1000 --bounded-codegen

// A deposit adds an amount to the existing balance and computes a new commitment with a new randomness. All, the old commitment, the new commitment, and a commitment to the amount need to go on chain, such that the proof can be verified.
pub fn main(
    old_balance: Field,
    old_r: Field,
    amount: Field,
    amount_r: Field,
    new_r: Field,
) -> pub (Field, Field, Field) {
    private_deposit_common::deposit(old_balance, old_r, amount, amount_r, new_r)
}
