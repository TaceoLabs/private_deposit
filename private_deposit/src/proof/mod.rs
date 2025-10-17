pub mod actionquery;
pub mod circom;
pub mod deposit;
pub mod transaction;
pub mod transaction_batched;
pub mod withdraw;

use crate::data_structure::{DepositValuePlain, PrivateDeposit};
use ark_ff::PrimeField;
use co_noir::{AcirFormat, Bn254, Rep3AcvmType};
use co_noir_common::crs::ProverCrs;
use co_noir_to_r1cs::{
    noir::ultrahonk,
    trace::{MpcTraceHasher, TraceHasher},
};
use mpc_core::{
    gadgets::poseidon2::Poseidon2,
    protocols::{
        rep3::{self, Rep3PrimeFieldShare, Rep3State},
        rep3_ring::{self, Rep3RingShare, ring::bit::Bit},
    },
};
use mpc_net::Network;
use noirc_artifacts::program::ProgramArtifact;
use rand::{CryptoRng, Rng};
use std::{collections::BTreeMap, sync::Arc};

// From the Noir circuits
const NUM_AMOUNT_BITS: usize = 64;
const NUM_WITHDRAW_NEW_BITS: usize = 100;
const DOMAIN_SEPARATOR: u64 = 0xDEADBEEFu64;

pub const NUM_BATCHED_TRANSACTIONS: usize = transaction_batched::NUM_TRANSACTIONS;

pub(super) type F = ark_bn254::Fr;
pub(super) type Curve = Bn254;

fn poseidon2_commitment_helper<const I: usize, const I2: usize, F: PrimeField, N: Network>(
    mut input: [Rep3PrimeFieldShare<F>; I2],
    net: &N,
    rep3_state: &mut Rep3State,
) -> eyre::Result<Vec<Vec<Rep3AcvmType<F>>>> {
    assert_eq!(2 * I, I2);
    let domain_separator = F::from(DOMAIN_SEPARATOR);
    let hasher = Poseidon2::<F, 2, 5>::default();
    let mut hasher_precomp = hasher.precompute_rep3(I, net, rep3_state)?;
    for input in input.iter_mut().step_by(2) {
        rep3::arithmetic::add_assign_public(input, domain_separator, rep3_state.id);
    }

    let mut result = Vec::with_capacity(I);
    let (_, traces) =
        hasher.hash_rep3_generate_noir_trace_many::<N, I, I2>(input, &mut hasher_precomp, net)?;
    for trace in traces {
        result.push(trace);
    }
    Ok(result)
}

fn poseidon2_plain_commitment_helper<const I: usize, const I2: usize, F: PrimeField>(
    mut input: [F; I2],
) -> Vec<Vec<Rep3AcvmType<F>>> {
    assert_eq!(2 * I, I2);
    let domain_separator = F::from(DOMAIN_SEPARATOR);
    let hasher = Poseidon2::<F, 2, 5>::default();

    for input in input.iter_mut().step_by(2) {
        *input += domain_separator;
    }

    let mut result = Vec::with_capacity(I);
    for input in input.chunks_exact(2) {
        let (_, trace) = hasher.hash_generate_noir_trace([input[0], input[1]]);
        let trace = trace
            .into_iter()
            .map(Rep3AcvmType::from)
            .collect::<Vec<Rep3AcvmType<F>>>();
        result.push(trace);
    }

    result
}

fn poseidon2_commitments<const I: usize, const I2: usize, F: PrimeField, N: Network>(
    mut input: [Rep3PrimeFieldShare<F>; I2],
    net: &N,
    rep3_state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    assert_eq!(2 * I, I2);
    let domain_separator = F::from(DOMAIN_SEPARATOR);
    let hasher = Poseidon2::<F, 2, 5>::default();
    let mut hasher_precomp = hasher.precompute_rep3(I, net, rep3_state)?;
    let mut result = Vec::with_capacity(I);
    for input in input.iter_mut().step_by(2) {
        result.push(input.to_owned());
        rep3::arithmetic::add_assign_public(input, domain_separator, rep3_state.id);
    }

    hasher.rep3_permutation_in_place_with_precomputation_packed(
        &mut input,
        &mut hasher_precomp,
        net,
    )?;
    for (des, src) in result.iter_mut().zip(input.iter().step_by(2)) {
        *des += src;
    }
    Ok(result)
}

#[expect(clippy::assertions_on_constants, clippy::type_complexity)]
pub(super) fn decompose_compose_for_transaction<N: Network>(
    amount: Rep3PrimeFieldShare<F>,
    sender_new: Rep3PrimeFieldShare<F>,
    net0: &N,
    net1: &N,
    rep3_state: &mut Rep3State,
) -> eyre::Result<(Vec<Rep3PrimeFieldShare<F>>, Vec<Rep3PrimeFieldShare<F>>)> {
    // let decomp_amount =
    //     rep3::yao::decompose_arithmetic(amount, net0, rep3_state, NUM_AMOUNT_BITS, 1)?;
    // let decomp_sender = rep3::yao::decompose_arithmetic(
    //     sender_new,
    //     net1,
    //     rep3_state,
    //     NUM_WITHDRAW_NEW_BITS,
    //     1,
    // )?;

    let a2b_amount = rep3::conversion::a2y2b(amount, net0, rep3_state)?;
    let a2b_sender = rep3::conversion::a2y2b(sender_new, net1, rep3_state)?;

    let mut to_compose = Vec::with_capacity(NUM_AMOUNT_BITS + NUM_WITHDRAW_NEW_BITS);
    assert!(NUM_AMOUNT_BITS <= 64);
    assert!(NUM_WITHDRAW_NEW_BITS <= 128);
    assert!(NUM_WITHDRAW_NEW_BITS > 64);
    let mut a2b_amount_a = a2b_amount.a.to_u64_digits()[0];
    let mut a2b_amount_b = a2b_amount.b.to_u64_digits()[0];
    let a2b_sender_a = a2b_sender.a.to_u64_digits();
    let a2b_sender_b = a2b_sender.b.to_u64_digits();
    let mut a2b_sender_a = ((a2b_sender_a[1] as u128) << 64) | a2b_sender_a[0] as u128;
    let mut a2b_sender_b = ((a2b_sender_b[1] as u128) << 64) | a2b_sender_b[0] as u128;
    for _ in 0..NUM_AMOUNT_BITS {
        let bit = Rep3RingShare::new(
            Bit::new((a2b_amount_a & 1) == 1),
            Bit::new((a2b_amount_b & 1) == 1),
        );
        to_compose.push(bit);
        a2b_amount_a >>= 1;
        a2b_amount_b >>= 1;
    }
    for _ in 0..NUM_WITHDRAW_NEW_BITS {
        let bit = Rep3RingShare::new(
            Bit::new((a2b_sender_a & 1) == 1),
            Bit::new((a2b_sender_b & 1) == 1),
        );
        to_compose.push(bit);
        a2b_sender_a >>= 1;
        a2b_sender_b >>= 1;
    }
    let mut composed =
        rep3_ring::conversion::bit_inject_from_bits_to_field_many(&to_compose, net0, rep3_state)?;

    let decomp_sender = composed.split_off(NUM_AMOUNT_BITS);
    Ok((composed, decomp_sender))
}

// Same as decompose_compose_for_transaction but without range check on the result_amount
#[expect(clippy::assertions_on_constants)]
pub(super) fn decompose_compose_for_deposit<N: Network>(
    amount: Rep3PrimeFieldShare<F>,
    net0: &N,
    rep3_state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    // let decomp_amount =
    //     rep3::yao::decompose_arithmetic(amount, net0, rep3_state, NUM_AMOUNT_BITS, 1)?;

    let a2b_amount = rep3::conversion::a2y2b(amount, net0, rep3_state)?;

    let mut to_compose = Vec::with_capacity(NUM_AMOUNT_BITS);
    assert!(NUM_AMOUNT_BITS <= 64);
    let mut a2b_amount_a = a2b_amount.a.to_u64_digits()[0];
    let mut a2b_amount_b = a2b_amount.b.to_u64_digits()[0];
    for _ in 0..NUM_AMOUNT_BITS {
        let bit = Rep3RingShare::new(
            Bit::new((a2b_amount_a & 1) == 1),
            Bit::new((a2b_amount_b & 1) == 1),
        );
        to_compose.push(bit);
        a2b_amount_a >>= 1;
        a2b_amount_b >>= 1;
    }

    rep3_ring::conversion::bit_inject_from_bits_to_field_many(&to_compose, net0, rep3_state)
}

pub struct TestConfig {}

impl TestConfig {
    const ROOT: &str = std::env!("CARGO_MANIFEST_DIR");
    const PROVER_CRS: &str = "/data/bn254_g1.dat";
    const VERIFIER_CRS: &str = "/data/bn254_g2.dat";
    const DEPOSIT_CIRCUIT: &str = "/data/private_deposit.json";
    const WITHDRAW_CIRCUIT: &str = "/data/private_withdraw.json";
    const TRANSACTION_CIRCUIT: &str = "/data/private_transaction.json";
    const TRANSACTION_BATCHED_CIRCUIT: &str = "/data/private_transaction_batched.json";

    #[cfg(test)]
    const NUM_ITEMS: usize = 1000;
    #[cfg(test)]
    const TEST_RUNS: usize = 5;

    pub fn install_tracing() {
        use tracing_subscriber::fmt::format::FmtSpan;
        use tracing_subscriber::prelude::*;
        use tracing_subscriber::{EnvFilter, fmt};

        let fmt_layer = fmt::layer()
            .with_target(false)
            .with_line_number(false)
            .with_span_events(FmtSpan::CLOSE | FmtSpan::ENTER);
        let filter_layer = EnvFilter::try_from_default_env()
            .or_else(|_| EnvFilter::try_new("warn,private_deposit=info,deposit=info"))
            .unwrap();

        tracing_subscriber::registry()
            .with(filter_layer)
            .with(fmt_layer)
            .init();
    }

    pub fn get_deposit_program_artifact() -> eyre::Result<ProgramArtifact> {
        let cs_path = format!("{}{}", Self::ROOT, Self::DEPOSIT_CIRCUIT);
        ultrahonk::get_program_artifact(cs_path)
    }

    pub fn get_withdraw_program_artifact() -> eyre::Result<ProgramArtifact> {
        let cs_path = format!("{}{}", Self::ROOT, Self::WITHDRAW_CIRCUIT);
        ultrahonk::get_program_artifact(cs_path)
    }

    pub fn get_transaction_program_artifact() -> eyre::Result<ProgramArtifact> {
        let cs_path = format!("{}{}", Self::ROOT, Self::TRANSACTION_CIRCUIT);
        ultrahonk::get_program_artifact(cs_path)
    }

    pub fn get_transaction_batched_program_artifact() -> eyre::Result<ProgramArtifact> {
        let cs_path = format!("{}{}", Self::ROOT, Self::TRANSACTION_BATCHED_CIRCUIT);
        ultrahonk::get_program_artifact(cs_path)
    }

    pub fn get_prover_crs(
        constraint_system: &AcirFormat<ark_bn254::Fr>,
    ) -> eyre::Result<Arc<ProverCrs<ark_bn254::G1Projective>>> {
        let prover_crs_path = format!("{}{}", Self::ROOT, Self::PROVER_CRS);
        let cirucit_size = ultrahonk::get_circuit_size(constraint_system).unwrap();
        ultrahonk::get_prover_crs(prover_crs_path, cirucit_size)
    }

    pub fn get_verifier_crs() -> eyre::Result<ark_bn254::G2Affine> {
        let verifier_crs_path = format!("{}{}", Self::ROOT, Self::VERIFIER_CRS);
        ultrahonk::get_verifier_crs(verifier_crs_path)
    }

    pub fn get_random_plain_map<F: PrimeField, R: Rng + CryptoRng>(
        num_items: usize,
        rng: &mut R,
    ) -> PrivateDeposit<F, DepositValuePlain<F>> {
        let mut map: PrivateDeposit<F, crate::data_structure::DepositValue<F>> =
            PrivateDeposit::with_capacity(num_items);
        for _ in 0..num_items {
            let key = F::rand(rng);
            let amount = F::from(rng.gen_range(0..u32::MAX)); // We don't use the full u64 range to avoid overflows in the testcases
            let blinding = F::rand(rng);
            // We don't check whether the key is already in the map since the probability is negligible
            map.insert(key, DepositValuePlain::new(amount, blinding));
        }
        assert_eq!(map.len(), num_items);
        map
    }

    // Hashmap is not ordered, so we need to convert it to an ordered map first to be consistent among multiple runs
    pub fn get_random_map_key<K, V, R: Rng>(map: &PrivateDeposit<K, V>, rng: &mut R) -> K
    where
        K: std::hash::Hash + Eq + Clone + Ord,
    {
        let ordered_map = BTreeMap::from_iter(map.iter());

        let index = rng.r#gen_range(0..ordered_map.len());
        ordered_map.keys().nth(index).unwrap().to_owned().to_owned()
    }
}
