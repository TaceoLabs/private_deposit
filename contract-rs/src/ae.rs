use ark_ec::CurveGroup;
use mpc_core::gadgets::poseidon2::Poseidon2;

pub(crate) fn dh_key_derivation(
    my_sk: &ark_babyjubjub::Fr,
    their_pk: ark_babyjubjub::EdwardsAffine,
) -> ark_babyjubjub::Fq {
    (their_pk * my_sk).into_affine().x
}

// Absorb 2, squeeze 2,  domainsep = 0x4142
// [0x80000002, 0x00000002, 0x4142]
const T2_DS: u128 = 0x80000002000000024142;
// Returns the used domain separator as a field element for the encryption
pub(crate) fn get_t2_ds() -> ark_babyjubjub::Fq {
    ark_babyjubjub::Fq::from(T2_DS)
}

pub(crate) fn sym_encrypt(
    key: ark_babyjubjub::Fq,
    mut msg: [ark_babyjubjub::Fq; 2],
    nonce: ark_babyjubjub::Fq,
) -> [ark_babyjubjub::Fq; 2] {
    let poseidon2_3 = Poseidon2::<_, 3, 5>::default();
    let ks = poseidon2_3.permutation(&[get_t2_ds(), key, nonce]);
    msg[0] += ks[1];
    msg[1] += ks[2];
    msg
}

pub(crate) fn sym_decrypt(
    key: ark_babyjubjub::Fq,
    mut ciphertext: [ark_babyjubjub::Fq; 2],
    nonce: ark_babyjubjub::Fq,
) -> [ark_babyjubjub::Fq; 2] {
    let poseidon2_3 = Poseidon2::<_, 3, 5>::default();
    let ks = poseidon2_3.permutation(&[get_t2_ds(), key, nonce]);
    ciphertext[0] -= ks[1];
    ciphertext[1] -= ks[2];
    ciphertext
}
