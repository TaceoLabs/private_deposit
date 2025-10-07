#[oracle(__debug_poseidon_start)]
unconstrained fn __debug_poseidon_start() {}
#[oracle(__debug_poseidon_end)]
unconstrained fn __debug_poseidon_end() {}

unconstrained fn mark_poseidon_start() {
    __debug_poseidon_start()
}
unconstrained fn mark_poseidon_end() {
    __debug_poseidon_end()
}

fn safe_mark_poseidon_start() {
    // Safety: This function is only a marker
    unsafe {
        mark_poseidon_start();
    }
}
fn safe_mark_poseidon_end() {
    // Safety: This function is only a marker
    unsafe {
        mark_poseidon_end();
    }
}

// Hashing as a compression function with t=2 and feed-forward
pub fn hash2(left: Field, right: Field) -> Field {
    let domain_sep = 0xDEADBEEF as Field;
    let input = left + domain_sep;
    safe_mark_poseidon_start();
    let state = poseidon2::bn254::hash_2([input, right]);
    safe_mark_poseidon_end();
    state + left // Feed forward
}

// Hashing using the Poseidon2 Blackbox function as a sponge
pub fn hash2_bb(left: Field, right: Field) -> Field {
    let domain_sep = 0xDEADBEEF as Field;
    let state = std::hash::poseidon2_permutation([domain_sep, left, right, 0], 4);
    state[0]
}

pub fn commit1(value: Field, r: Field) -> Field {
    // crate::hash::hash2(value, r)
    crate::hash::hash2_bb(value, r)
}
