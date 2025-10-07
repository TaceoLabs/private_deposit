pub mod deposit;

#[cfg(test)]
use crate::data_structure::{DepositValuePlain, PrivateDeposit};
#[cfg(test)]
use ark_ff::PrimeField;
#[cfg(test)]
use co_noir::{AcirFormat, Bn254};
#[cfg(test)]
use co_ultrahonk::prelude::ProverCrs;
#[cfg(test)]
use noirc_artifacts::program::ProgramArtifact;
#[cfg(test)]
use oblivious_map_proof::noir::ultrahonk;
#[cfg(test)]
use rand::{CryptoRng, Rng};
#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
pub(crate) struct TestConfig {}

#[cfg(test)]
impl TestConfig {
    const ROOT: &str = std::env!("CARGO_MANIFEST_DIR");
    const PROVER_CRS: &str = "/data/bn254_g1.dat";
    const VERIFIER_CRS: &str = "/data/bn254_g2.dat";
    const DEPOSIT_CIRCUIT: &str = "/data/private_deposit.json";

    const NUM_ITEMS: usize = 100;
    const TEST_RUNS: usize = 5;

    #[allow(dead_code)]
    pub fn install_tracing() {
        use tracing_subscriber::fmt::format::FmtSpan;
        use tracing_subscriber::prelude::*;
        use tracing_subscriber::{EnvFilter, fmt};

        let fmt_layer = fmt::layer()
            .with_target(false)
            .with_line_number(false)
            .with_span_events(FmtSpan::CLOSE | FmtSpan::ENTER);
        let filter_layer = EnvFilter::try_from_default_env()
            .or_else(|_| EnvFilter::try_new("info"))
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

    pub fn get_prover_crs(
        constraint_system: &AcirFormat<ark_bn254::Fr>,
    ) -> eyre::Result<Arc<ProverCrs<Bn254>>> {
        let prover_crs_path = format!("{}{}", Self::ROOT, Self::PROVER_CRS);
        let cirucit_size = ultrahonk::get_circuit_size(constraint_system).unwrap();
        ultrahonk::get_prver_crs(prover_crs_path, cirucit_size)
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
            let amount = F::from(rng.r#gen::<u64>());
            let blinding = F::rand(rng);
            // We don't check whether the key is already in the map since the probability is negligible
            map.insert(key, DepositValuePlain::new(amount, blinding));
        }
        assert_eq!(map.len(), num_items);
        map
    }

    #[expect(unused)]
    pub fn get_random_map_key<K, V, R: Rng>(map: &PrivateDeposit<K, V>, rng: &mut R) -> K
    where
        K: std::hash::Hash + Eq + Clone,
    {
        let index = rng.r#gen_range(0..map.len());
        map.keys().nth(index).unwrap().clone()
    }
}
