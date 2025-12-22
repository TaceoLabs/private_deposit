pub mod actionquery;
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
use mpc_core::{
    gadgets::poseidon2::Poseidon2,
    protocols::rep3::{self, Rep3PrimeFieldShare, Rep3State},
};
use mpc_net::Network;
use rand::{CryptoRng, Rng};
use std::path::PathBuf;

pub(crate) fn poseidon2_circom_commitment_helper<
    const I: usize,
    const I2: usize,
    F: PrimeField,
    N: Network,
>(
    mut input: [Rep3PrimeFieldShare<F>; I2],
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
        .rep3_permutation_in_place_with_precomputation_intermediate_packed::<N, I2>(
            input,
            &mut hasher_precomp,
            net,
        )?;
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

pub(crate) fn poseidon2_plain_circom_commitment_helper<
    const I: usize,
    const I2: usize,
    F: PrimeField,
>(
    mut input: [F; I2],
) -> eyre::Result<Vec<([F; 2], Vec<F>)>> {
    const T: usize = 2;
    assert_eq!(T * I, I2);
    let domain_separator = F::from(DOMAIN_SEPARATOR);
    let hasher = Poseidon2::<F, T, 5>::default();
    for input in input.iter_mut().step_by(T) {
        *input += domain_separator;
    }

    let mut result = Vec::with_capacity(I);
    for input in input.chunks_exact(2) {
        result.push(hasher.plain_permutation_intermediate([input[0], input[1]])?);
    }
    Ok(result)
}

impl TestConfig {
    const CIRCOM_LIB: &str = "/../circom";
    const DEPOSIT_CIRCOM: &str = "/../circom/main/deposit.circom";
    const WITHDRAW_CIRCOM: &str = "/../circom/main/withdraw.circom";
    const TRANSACTION_CIRCOM: &str = "/../circom/main/transaction.circom";
    const TRANSACTION_BATCHED_CIRCOM: &str = "/../circom/main/transaction_batched.circom";
    const DEPOSIT_R1CS: &str = "/../circom/main/deposit.r1cs";
    const WITHDRAW_R1CS: &str = "/../circom/main/withdraw.r1cs";
    const TRANSACTION_R1CS: &str = "/../circom/main/transaction.r1cs";
    const TRANSACTION_BATCHED_R1CS: &str = "/../circom/main/transaction_batched.r1cs";

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

    pub fn get_transaction_batched_proof_schema<R: Rng + CryptoRng>(
        rng: &mut R,
    ) -> eyre::Result<CircomProofSchema<Bn254>> {
        let r1cs = format!("{}{}", Self::ROOT, Self::TRANSACTION_BATCHED_R1CS);
        CircomProofSchema::from_r1cs_file(PathBuf::from(r1cs), rng)
            .context("while reading r1cs file")
    }
}
