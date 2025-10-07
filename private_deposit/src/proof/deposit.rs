use crate::{
    data_structure::{DepositValue, PrivateDeposit},
    proof::Rep3NetworkState,
};
use ark_ff::Zero;
use co_noir::{AcirFormat, Bn254, Rep3AcvmType};
use co_ultrahonk::prelude::{HonkProof, ProverCrs};
use mpc_core::protocols::rep3::Rep3PrimeFieldShare;
use mpc_net::Network;
use noirc_artifacts::program::ProgramArtifact;
use oblivious_map_proof::noir::ultrahonk;

type F = ark_bn254::Fr;

impl<K> PrivateDeposit<K, DepositValue<F>>
where
    K: std::hash::Hash + Eq,
{
    #[expect(clippy::too_many_arguments)]
    pub fn deposit_with_ultrahonk_proof<N: Network>(
        &mut self,
        key: K,
        amount: Rep3PrimeFieldShare<F>,
        amount_blinding: Rep3PrimeFieldShare<F>, // For the commitment to the amount
        program_artifact: ProgramArtifact,
        constraint_system: &AcirFormat<F>,
        prover_crs: &ProverCrs<Bn254>,
        network: &mut Rep3NetworkState<N>,
    ) -> eyre::Result<(DepositValue<F>, HonkProof<F>, Vec<F>)> {
        let (old, new) = self.deposit(key, amount, network.rep3_state);

        let mut inputs = Vec::with_capacity(5);
        if let Some(old) = old {
            inputs.push(Rep3AcvmType::from(old.amount));
            inputs.push(Rep3AcvmType::from(old.blinding));
        } else {
            inputs.push(Rep3AcvmType::from(F::zero()));
            inputs.push(Rep3AcvmType::from(F::zero()));
        }
        inputs.push(Rep3AcvmType::from(amount));
        inputs.push(Rep3AcvmType::from(amount_blinding));
        inputs.push(Rep3AcvmType::from(new.blinding));

        let witness = ultrahonk::conoir_witness_extension(
            inputs,
            program_artifact,
            network.net0,
            network.net1,
        )?;

        let (proof, public_inputs) = ultrahonk::prove(
            constraint_system,
            witness,
            prover_crs,
            network.net0,
            network.net1,
        )?;

        Ok((new, proof, public_inputs))
    }
}

// #[cfg(test)]
// mod tests {
//     const ROOT: &str = std::env!("CARGO_MANIFEST_DIR");
//     const PROVER_CRS: &str = "/data/bn254_g1.dat";
//     const VERIFIER_CRS: &str = "/data/bn254_g2.dat";
//     const CIRCUIT: &str = "/data/private_deposit.json";
// }
