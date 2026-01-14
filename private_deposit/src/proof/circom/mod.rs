pub mod actionquery;
pub mod actionquery_compressed;
pub mod deposit;
pub mod transaction;
pub mod transaction_batched;
pub mod withdraw;

use crate::proof::{DOMAIN_SEPARATOR, TestConfig};
use ark_ff::PrimeField;
use circom_mpc_vm::{ComponentAcceleratorOutput, Rep3VmType};
use co_circom::CoCircomCompilerParsed;
use co_noir::Bn254;
use co_noir_to_r1cs::circom::proof_schema::CircomProofSchema;
use eyre::Context;
use mpc_core::gadgets::poseidon2::{CircomTraceBatchedHasher, CircomTracePlainHasher};
use mpc_core::protocols::rep3::arithmetic;
use mpc_core::{
    gadgets::poseidon2::Poseidon2,
    protocols::rep3::{self, Rep3PrimeFieldShare, Rep3State},
};
use mpc_net::Network;
use num_bigint::BigUint;
use rand::{CryptoRng, Rng};
use sha2::{self, Digest, Sha256};
use std::path::PathBuf;

pub(crate) const CIRCOM_MAP_LABELS: [&str; 8] = [
    "sender_old_balance",
    "sender_old_r",
    "receiver_old_balance",
    "receiver_old_r",
    "amount",
    "amount_r",
    "sender_new_r",
    "receiver_new_r",
];
pub(crate) const POSEIDON2_SPONGE_T: usize = 16; // Must match the one in the circom circuit (circom/main/transaction_batched_compressed.circom)

pub(crate) fn poseidon2_circom_commitment_helper<
    const I: usize,
    const I2: usize,
    F: PrimeField,
    N: Network,
>(
    input: &mut [Rep3PrimeFieldShare<F>; I2],
    net: &N,
    rep3_state: &mut Rep3State,
) -> eyre::Result<Vec<ComponentAcceleratorOutput<Rep3VmType<F>>>> {
    const T: usize = 2;
    assert_eq!(T * I, I2);
    let domain_separator = F::from(DOMAIN_SEPARATOR);
    let hasher = Poseidon2::<F, T, 5>::default();
    let mut hasher_precomp = hasher.precompute_rep3(I, net, rep3_state)?;
    for input in input.iter_mut().step_by(T) {
        rep3::arithmetic::add_assign_public(input, domain_separator, rep3_state.id);
    }

    let mut result = Vec::with_capacity(I);
    let (states, traces) = hasher
        .rep3_permutation_in_place_with_precomputation_intermediate_packed::<N, I2, I>(
            *input,
            &mut hasher_precomp,
            net,
        )?;
    *input = states;
    for (state, trace) in states.chunks(T).zip(traces) {
        result.push(ComponentAcceleratorOutput::new(
            state
                .iter()
                .map(|x| (*x).into())
                .collect::<Vec<Rep3VmType<F>>>(),
            trace
                .iter()
                .map(|x| (*x).into())
                .collect::<Vec<Rep3VmType<F>>>(),
        ));
    }
    Ok(result)
}

pub(crate) fn feed_forward_shared<
    const T: usize,
    const I: usize,
    const I2: usize,
    F: PrimeField,
>(
    commitments: [Rep3PrimeFieldShare<F>; I2],
    input: [Rep3PrimeFieldShare<F>; I2],
) -> [Rep3PrimeFieldShare<F>; I] {
    assert_eq!(T * I, I2);
    std::array::from_fn(|i| {
        let idx = i * T;
        arithmetic::add(input[idx], commitments[idx])
    })
}

pub(crate) fn feed_forward_public<
    const T: usize,
    const I: usize,
    const I2: usize,
    F: PrimeField,
>(
    commitments: [F; I2],
    input: [F; I2],
) -> [F; I] {
    assert_eq!(T * I, I2);
    std::array::from_fn(|i| {
        let idx = i * T;
        input[idx] + commitments[idx]
    })
}

pub(crate) fn compression_commitment_helper<
    const T_SPONGE: usize,
    const I: usize,
    F: PrimeField,
>(
    opened_commitments: [F; I],
) -> eyre::Result<(Vec<ComponentAcceleratorOutput<Rep3VmType<F>>>, F)> {
    let opened_commitments_as_bytes = opened_commitments
        .iter()
        .flat_map(|x| {
            let x: BigUint = (*x).into();
            let mut bytes = x.to_bytes_be();
            while bytes.len() < 32 {
                bytes.insert(0, 0u8);
            }
            bytes
        })
        .collect::<Vec<u8>>();

    let mut hasher = Sha256::new();
    hasher.update(opened_commitments_as_bytes);
    let sha_hash = hasher.finalize();
    let alpha = F::from_be_bytes_mod_order(&sha_hash);

    let (beta_traces, _) =
        poseidon2_plain_sponge_circom_helper::<T_SPONGE, I, _>(opened_commitments)?;

    Ok((beta_traces, alpha))
}

fn poseidon2_plain_sponge_circom_helper<const T: usize, const I2: usize, F: PrimeField>(
    input: [F; I2],
) -> eyre::Result<(Vec<ComponentAcceleratorOutput<Rep3VmType<F>>>, F)> {
    let domain_separator = F::from(DOMAIN_SEPARATOR);
    let hasher = Poseidon2::<F, T, 5>::default();
    let permutations = I2.div_ceil(T - 1);
    let mut states = vec![[F::zero(); T]; permutations + 1];

    // Initialize the state
    states[0][T - 1] = domain_separator;

    let mut traces = Vec::with_capacity(permutations);
    let mut absorbed = 0;
    for p in 0..permutations {
        let mut remaining = I2 - absorbed;
        if remaining >= T - 1 {
            remaining = T - 1;
        }
        for i in 0..remaining {
            states[p][i] += input[absorbed + i];
        }
        absorbed += remaining;
        let res = hasher.plain_permutation_intermediate(states[p])?;
        states[p + 1] = res.0;
        traces.push(ComponentAcceleratorOutput::new(
            res.0.iter().map(|x| (*x).into()).collect(),
            res.1.iter().map(|x| (*x).into()).collect(),
        ));
    }

    Ok((traces, states[permutations][0]))
}

// NOTE FF: I checked and apparently the muls in the uhf computation are only public*shared or public*public, so precomputation is not needed
#[expect(unused)]
fn compute_uhf<F: PrimeField, const N: usize>(alpha: F, beta: F, q: [F; N]) -> (Vec<F>, F) {
    assert!(N >= 1);

    let seed = alpha + beta;
    let mut muls = vec![F::zero(); N];

    for i in N - 1..0 {
        muls[i - 1] = seed * (q[i] + muls[i]);
    }
    let gamma = muls[0] + q[0];
    (muls, gamma)
}

pub(crate) fn poseidon2_plain_circom_commitment_helper<
    const T: usize,
    const I: usize,
    const I2: usize,
    F: PrimeField,
>(
    mut input: [F; I2],
) -> eyre::Result<Vec<([F; T], Vec<F>)>> {
    assert_eq!(T * I, I2);
    let domain_separator = F::from(DOMAIN_SEPARATOR);
    let hasher = Poseidon2::<F, T, 5>::default();
    for input in input.iter_mut().step_by(T) {
        *input += domain_separator;
    }

    let mut result = Vec::with_capacity(I);
    for input in input.chunks_exact(T) {
        result.push(
            hasher
                .plain_permutation_intermediate(input.try_into().expect("we take exact chunks"))?,
        );
    }
    Ok(result)
}

impl TestConfig {
    const CIRCOM_LIB: &str = "/../circom";
    const DEPOSIT_CIRCOM: &str = "/../circom/main/deposit.circom";
    const WITHDRAW_CIRCOM: &str = "/../circom/main/withdraw.circom";
    const TRANSACTION_CIRCOM: &str = "/../circom/main/transaction.circom";
    const TRANSACTION_BATCHED_CIRCOM: &str = "/../circom/main/transaction_batched.circom";
    const TRANSACTION_BATCHED_COMPRESSED_CIRCOM: &str =
        "/../circom/main/transaction_batched_compressed.circom";
    const DEPOSIT_R1CS: &str = "/../circom/main/deposit.r1cs";
    const WITHDRAW_R1CS: &str = "/../circom/main/withdraw.r1cs";
    const TRANSACTION_R1CS: &str = "/../circom/main/transaction.r1cs";
    const TRANSACTION_BATCHED_R1CS: &str = "/../circom/main/transaction_batched.r1cs";
    const TRANSACTION_BATCHED_COMPRESSED_R1CS: &str =
        "/../circom/main/transaction_batched_compressed.r1cs";

    pub fn get_deposit_circom() -> eyre::Result<CoCircomCompilerParsed<ark_bn254::Fr>> {
        let lib = format!("{}{}", Self::ROOT, Self::CIRCOM_LIB);
        let circuit = format!("{}{}", Self::ROOT, Self::DEPOSIT_CIRCOM);
        CircomProofSchema::<Bn254>::read_circuit_co_circom(
            PathBuf::from(circuit),
            PathBuf::from(lib),
        )
    }

    pub fn get_deposit_proof_schema<R: Rng + CryptoRng>(
        rng: &mut R,
    ) -> eyre::Result<CircomProofSchema<Bn254>> {
        let r1cs = format!("{}{}", Self::ROOT, Self::DEPOSIT_R1CS);
        CircomProofSchema::from_r1cs_file(PathBuf::from(r1cs), rng)
            .context("while reading r1cs file")
    }

    pub fn get_withdraw_circom() -> eyre::Result<CoCircomCompilerParsed<ark_bn254::Fr>> {
        let lib = format!("{}{}", Self::ROOT, Self::CIRCOM_LIB);
        let circuit = format!("{}{}", Self::ROOT, Self::WITHDRAW_CIRCOM);
        CircomProofSchema::<Bn254>::read_circuit_co_circom(
            PathBuf::from(circuit),
            PathBuf::from(lib),
        )
    }

    pub fn get_withdraw_proof_schema<R: Rng + CryptoRng>(
        rng: &mut R,
    ) -> eyre::Result<CircomProofSchema<Bn254>> {
        let r1cs = format!("{}{}", Self::ROOT, Self::WITHDRAW_R1CS);
        CircomProofSchema::from_r1cs_file(PathBuf::from(r1cs), rng)
            .context("while reading r1cs file")
    }

    pub fn get_transaction_circom() -> eyre::Result<CoCircomCompilerParsed<ark_bn254::Fr>> {
        let lib = format!("{}{}", Self::ROOT, Self::CIRCOM_LIB);
        let circuit = format!("{}{}", Self::ROOT, Self::TRANSACTION_CIRCOM);
        CircomProofSchema::<Bn254>::read_circuit_co_circom(
            PathBuf::from(circuit),
            PathBuf::from(lib),
        )
    }

    pub fn get_transaction_proof_schema<R: Rng + CryptoRng>(
        rng: &mut R,
    ) -> eyre::Result<CircomProofSchema<Bn254>> {
        let r1cs = format!("{}{}", Self::ROOT, Self::TRANSACTION_R1CS);
        CircomProofSchema::from_r1cs_file(PathBuf::from(r1cs), rng)
            .context("while reading r1cs file")
    }

    pub fn get_transaction_batched_circom() -> eyre::Result<CoCircomCompilerParsed<ark_bn254::Fr>> {
        let lib = format!("{}{}", Self::ROOT, Self::CIRCOM_LIB);
        let circuit = format!("{}{}", Self::ROOT, Self::TRANSACTION_BATCHED_CIRCOM);
        CircomProofSchema::<Bn254>::read_circuit_co_circom(
            PathBuf::from(circuit),
            PathBuf::from(lib),
        )
    }

    pub fn get_transaction_batched_circom_compressed()
    -> eyre::Result<CoCircomCompilerParsed<ark_bn254::Fr>> {
        let lib = format!("{}{}", Self::ROOT, Self::CIRCOM_LIB);
        let circuit = format!(
            "{}{}",
            Self::ROOT,
            Self::TRANSACTION_BATCHED_COMPRESSED_CIRCOM
        );
        CircomProofSchema::<Bn254>::read_circuit_co_circom(
            PathBuf::from(circuit),
            PathBuf::from(lib),
        )
    }

    pub fn get_transaction_batched_proof_schema<R: Rng + CryptoRng>(
        rng: &mut R,
    ) -> eyre::Result<CircomProofSchema<Bn254>> {
        let r1cs = format!("{}{}", Self::ROOT, Self::TRANSACTION_BATCHED_R1CS);
        CircomProofSchema::from_r1cs_file(PathBuf::from(r1cs), rng)
            .context("while reading r1cs file")
    }

    pub fn get_transaction_batched_proof_schema_compressed<R: Rng + CryptoRng>(
        rng: &mut R,
    ) -> eyre::Result<CircomProofSchema<Bn254>> {
        let r1cs = format!(
            "{}{}",
            Self::ROOT,
            Self::TRANSACTION_BATCHED_COMPRESSED_R1CS
        );
        CircomProofSchema::from_r1cs_file(PathBuf::from(r1cs), rng)
            .context("while reading r1cs file")
    }
}
