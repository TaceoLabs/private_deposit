use crate::data_structure::{DepositValueShare, PrivateDeposit};
use ark_groth16::Proof;
use co_circom::{ConstraintMatrices, ProvingKey, Rep3SharedWitness};
use co_noir::{AcirFormat, HonkProof, Rep3AcvmType};
use co_noir_to_r1cs::{
    noir::{r1cs, ultrahonk},
    r1cs::noir_proof_schema::NoirProofScheme,
};
use co_ultrahonk::prelude::ProverCrs;
use eyre::Context;
use mpc_core::protocols::rep3::{Rep3PrimeFieldShare, Rep3State};
use mpc_net::Network;
use noirc_artifacts::program::ProgramArtifact;

use super::Curve;
use super::F;

const NUM_WITHDRAW_COMMITMENTS: usize = 3;

impl<K> PrivateDeposit<K, DepositValueShare<F>>
where
    K: std::hash::Hash + Eq,
{
    fn get_withdraw_input(
        old: DepositValueShare<F>,
        amount: Rep3PrimeFieldShare<F>,
        amount_blinding: Rep3PrimeFieldShare<F>,
        new_blinding: Rep3PrimeFieldShare<F>,
    ) -> Vec<Rep3AcvmType<F>> {
        vec![
            Rep3AcvmType::from(old.amount),
            Rep3AcvmType::from(old.blinding),
            Rep3AcvmType::from(amount),
            Rep3AcvmType::from(amount_blinding),
            Rep3AcvmType::from(new_blinding),
        ]
    }

    pub fn withdraw_with_commitments<N: Network>(
        &mut self,
        key: K,
        amount: Rep3PrimeFieldShare<F>,
        amount_blinding: Rep3PrimeFieldShare<F>, // For the commitment to the amount
        net0: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(DepositValueShare<F>, Vec<Rep3PrimeFieldShare<F>>)> {
        let (old, new) = self.withdraw(key, amount, rep3_state)?;

        let commitments = super::poseidon2_commitments::<NUM_WITHDRAW_COMMITMENTS, _, _, _>(
            [
                old.amount,
                old.blinding,
                new.amount,
                new.blinding,
                amount,
                amount_blinding,
            ],
            net0,
            rep3_state,
        )?;
        Ok((new, commitments))
    }

    #[expect(clippy::too_many_arguments)]
    pub fn withdraw_with_ultrahonk_proof<N: Network>(
        &mut self,
        key: K,
        amount: Rep3PrimeFieldShare<F>,
        amount_blinding: Rep3PrimeFieldShare<F>, // For the commitment to the amount
        program_artifact: ProgramArtifact,
        constraint_system: &AcirFormat<F>,
        prover_crs: &ProverCrs<ark_bn254::G1Projective>,
        net0: &N,
        net1: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(DepositValueShare<F>, HonkProof<F>, Vec<F>)> {
        let (old, new) = self.withdraw(key, amount, rep3_state)?;

        let inputs =
            Self::get_withdraw_input(old.to_owned(), amount, amount_blinding, new.blinding);

        // let witness_stack =
        //     ultrahonk::conoir_witness_extension(inputs, program_artifact, net0, net1)?;
        let traces = super::poseidon2_commitment_helper::<NUM_WITHDRAW_COMMITMENTS, _, _, _>(
            [
                amount,
                amount_blinding,
                old.amount,
                old.blinding,
                new.amount,
                new.blinding,
            ],
            net0,
            rep3_state,
        )?;
        let witness_stack = ultrahonk::r1cs_witness_extension_with_helper(
            inputs,
            traces,
            program_artifact,
            net0,
            net1,
        )?;
        let witness = co_noir::witness_stack_to_vec_rep3(witness_stack);

        let (proof, public_inputs) =
            ultrahonk::prove(constraint_system, witness, prover_crs, net0, net1)?;

        Ok((new, proof, public_inputs))
    }

    #[expect(clippy::too_many_arguments)]
    pub fn withdraw_with_r1cs_witext<N: Network>(
        &mut self,
        key: K,
        amount: Rep3PrimeFieldShare<F>,
        amount_blinding: Rep3PrimeFieldShare<F>, // For the commitment to the amount
        proof_schema: &NoirProofScheme<F>,
        net0: &N,
        net1: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(DepositValueShare<F>, Rep3SharedWitness<F>)> {
        let (old, new) = self.withdraw(key, amount, rep3_state)?;

        let inputs =
            Self::get_withdraw_input(old.to_owned(), amount, amount_blinding, new.blinding);

        let traces = super::poseidon2_commitment_helper::<NUM_WITHDRAW_COMMITMENTS, _, _, _>(
            [
                amount,
                amount_blinding,
                old.amount,
                old.blinding,
                new.amount,
                new.blinding,
            ],
            net0,
            rep3_state,
        )?;
        let r1cs =
            r1cs::trace_to_r1cs_witness(inputs, traces, proof_schema, net0, net1, rep3_state)
                .context("while translating witness to R1CS")?;

        let witness = r1cs::r1cs_witness_to_cogroth16(proof_schema, r1cs, rep3_state.id);

        Ok((new, witness))
    }

    #[expect(clippy::too_many_arguments)]
    pub fn withdraw_with_groth16_proof<N: Network>(
        &mut self,
        key: K,
        amount: Rep3PrimeFieldShare<F>,
        amount_blinding: Rep3PrimeFieldShare<F>, // For the commitment to the amount
        proof_schema: &NoirProofScheme<F>,
        cs: &ConstraintMatrices<F>,
        pk: &ProvingKey<Curve>,
        net0: &N,
        net1: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(DepositValueShare<F>, Proof<Curve>, Vec<F>)> {
        let (new, witness) = self.withdraw_with_r1cs_witext(
            key,
            amount,
            amount_blinding,
            proof_schema,
            net0,
            net1,
            rep3_state,
        )?;

        let (proof, public_inputs) =
            r1cs::prove(cs, pk, witness, net0, net1).context("while generating Groth16 proof")?;

        Ok((new, proof, public_inputs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{data_structure::DepositValuePlain, proof::TestConfig};
    use ark_ff::{PrimeField, UniformRand, Zero};
    use itertools::izip;
    use mpc_core::protocols::rep3::{self, Rep3State, conversion::A2BType};
    use mpc_net::local::LocalNetwork;
    use rand::Rng;
    use std::{sync::Arc, thread};

    #[test]
    #[ignore = "UltraHonk tests are ignored at the moment"]
    fn withdraw_ultrahonk_test() {
        // TestConfig::install_tracing();

        // Init Ultrahonk
        // Read constraint system and keys
        let pa = TestConfig::get_withdraw_program_artifact().unwrap();
        let constraint_system = Arc::new(ultrahonk::get_constraint_system_from_artifact(&pa));
        let prover_crs = TestConfig::get_prover_crs(&constraint_system).unwrap();
        let verifier_crs = TestConfig::get_verifier_crs().unwrap();
        let vk_barretenberg =
            ultrahonk::generate_vk_barretenberg(&constraint_system, prover_crs.clone()).unwrap();
        let vk = ultrahonk::get_vk(vk_barretenberg, verifier_crs);

        // Init networks
        let mut test_network0 = LocalNetwork::new(3);
        let mut test_network1 = LocalNetwork::new(3);

        // Get a random map and its shares
        let mut rng = rand::thread_rng();
        let mut plain_map =
            TestConfig::get_random_plain_map::<F, _>(TestConfig::NUM_ITEMS, &mut rng);
        let mut map_shares = plain_map.share(&mut rng);

        // The actual testcase
        for _ in 0..TestConfig::TEST_RUNS {
            let key = TestConfig::get_random_map_key(&plain_map, &mut rng);
            let amount_blinding = F::rand(&mut rng);

            // Insert (just the amount) into the plain map
            let read_plain = plain_map.get(&key).unwrap();
            let max_amount = read_plain.amount.into_bigint().0[0];
            assert_eq!(F::from(max_amount), read_plain.amount); // Debug Assert
            let amount = F::from(rng.gen_range(0..=max_amount));
            let result_amount = read_plain.amount - amount;
            plain_map.insert(key, DepositValuePlain::new(result_amount, F::zero()));

            // Share the amount and the blinding
            let amount_share = rep3::share_field_element(amount, &mut rng);
            let amount_blinding_share = rep3::share_field_element(amount_blinding, &mut rng);

            // Do the MPC work
            let (read, proof, public_inputs) = thread::scope(|scope| {
                let mut handles = Vec::with_capacity(3);
                for (net0, net1, map, amount, amount_blinding) in izip!(
                    &mut test_network0,
                    &mut test_network1,
                    &mut map_shares,
                    amount_share,
                    amount_blinding_share
                ) {
                    let constraint_system = constraint_system.clone();
                    let pa = pa.clone();
                    let prover_crs = prover_crs.clone();

                    let handle = scope.spawn(move || {
                        let mut rep3 = Rep3State::new(net0, A2BType::default()).unwrap();

                        let (read, proof, public_inputs) = map
                            .withdraw_with_ultrahonk_proof(
                                key,
                                amount,
                                amount_blinding,
                                pa,
                                &constraint_system,
                                &prover_crs,
                                net0,
                                net1,
                                &mut rep3,
                            )
                            .unwrap();

                        (read, proof, public_inputs)
                    });
                    handles.push(handle);
                }

                let mut read = Vec::with_capacity(handles.len());
                let (read0, proof0, public_inputs0) = handles.remove(0).join().unwrap();
                read.push(read0.amount);
                for handle in handles {
                    let (read_, proof, public_inputs) = handle.join().unwrap();
                    assert_eq!(proof, proof0);
                    assert_eq!(public_inputs, public_inputs0);
                    read.push(read_.amount);
                }
                let read = rep3::combine_field_element(read[0], read[1], read[2]);
                (read, proof0, public_inputs0)
            });

            // Verifiy the results
            assert_eq!(result_amount, read);
            assert!(ultrahonk::verify(proof, &public_inputs, &vk).unwrap());
        }

        // Finally, compare the maps
        for (key, plain_value) in plain_map.into_iter() {
            let amount = plain_value.amount;
            let share0 = map_shares[0].remove(&key).unwrap().amount;
            let share1 = map_shares[1].remove(&key).unwrap().amount;
            let share2 = map_shares[2].remove(&key).unwrap().amount;
            let combined = rep3::combine_field_element(share0, share1, share2);
            assert_eq!(amount, combined);
        }
        assert!(map_shares[0].is_empty());
        assert!(map_shares[1].is_empty());
        assert!(map_shares[2].is_empty());
    }

    #[test]
    fn withdraw_groth16_test() {
        // TestConfig::install_tracing();

        // Init Groth16
        // Read constraint system
        let pa = TestConfig::get_withdraw_program_artifact().unwrap();

        // Get the R1CS proof schema
        let mut rng = rand::thread_rng();
        let (proof_schema, pk, cs) = r1cs::setup_r1cs(pa, &mut rng).unwrap();
        let proof_schema = Arc::new(proof_schema);
        let pk = Arc::new(pk);
        let cs = Arc::new(cs);
        let size = proof_schema.size();
        println!(
            "R1CS size: constraints = {}, witnesses = {}",
            size.0, size.1
        );

        // Init networks
        let mut test_network0 = LocalNetwork::new(3);
        let mut test_network1 = LocalNetwork::new(3);

        // Get a random map and its shares
        let mut plain_map =
            TestConfig::get_random_plain_map::<F, _>(TestConfig::NUM_ITEMS, &mut rng);
        let mut map_shares = plain_map.share(&mut rng);

        // The actual testcase
        for _ in 0..TestConfig::TEST_RUNS {
            let key = TestConfig::get_random_map_key(&plain_map, &mut rng);
            let amount_blinding = F::rand(&mut rng);

            // Insert (just the amount) into the plain map
            let read_plain = plain_map.get(&key).unwrap();
            let max_amount = read_plain.amount.into_bigint().0[0];
            assert_eq!(F::from(max_amount), read_plain.amount); // Debug Assert
            let amount = F::from(rng.gen_range(0..=max_amount));
            let result_amount = read_plain.amount - amount;
            plain_map.insert(key, DepositValuePlain::new(result_amount, F::zero()));

            // Share the amount and the blinding
            let amount_share = rep3::share_field_element(amount, &mut rng);
            let amount_blinding_share = rep3::share_field_element(amount_blinding, &mut rng);

            // Do the MPC work
            let (read, proof, public_inputs) = thread::scope(|scope| {
                let mut handles = Vec::with_capacity(3);
                for (net0, net1, map, amount, amount_blinding) in izip!(
                    &mut test_network0,
                    &mut test_network1,
                    &mut map_shares,
                    amount_share,
                    amount_blinding_share
                ) {
                    let proof_schema = proof_schema.clone();
                    let cs = cs.clone();
                    let pk = pk.clone();
                    let handle = scope.spawn(move || {
                        let mut rep3 = Rep3State::new(net0, A2BType::default()).unwrap();

                        let (read, proof, public_inputs) = map
                            .withdraw_with_groth16_proof(
                                key,
                                amount,
                                amount_blinding,
                                &proof_schema,
                                &cs,
                                &pk,
                                net0,
                                net1,
                                &mut rep3,
                            )
                            .unwrap();

                        (read, proof, public_inputs)
                    });
                    handles.push(handle);
                }

                let mut read = Vec::with_capacity(handles.len());
                let (read0, proof0, public_inputs0) = handles.remove(0).join().unwrap();
                read.push(read0.amount);
                for handle in handles {
                    let (read_, proof, public_inputs) = handle.join().unwrap();
                    assert_eq!(proof, proof0);
                    assert_eq!(public_inputs, public_inputs0);
                    read.push(read_.amount);
                }
                let read = rep3::combine_field_element(read[0], read[1], read[2]);
                (read, proof0, public_inputs0)
            });

            // Verifiy the results
            assert_eq!(result_amount, read);
            assert!(r1cs::verify(&pk.vk, &proof, &public_inputs).unwrap());
        }

        // Finally, compare the maps
        for (key, plain_value) in plain_map.into_iter() {
            let amount = plain_value.amount;
            let share0 = map_shares[0].remove(&key).unwrap().amount;
            let share1 = map_shares[1].remove(&key).unwrap().amount;
            let share2 = map_shares[2].remove(&key).unwrap().amount;
            let combined = rep3::combine_field_element(share0, share1, share2);
            assert_eq!(amount, combined);
        }
        assert!(map_shares[0].is_empty());
        assert!(map_shares[1].is_empty());
        assert!(map_shares[2].is_empty());
    }
}
