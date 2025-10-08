use crate::data_structure::{DepositValueShare, PrivateDeposit};
use ark_ff::Zero;
use ark_groth16::Proof;
use co_circom::{ConstraintMatrices, ProvingKey};
use co_noir::{AcirFormat, Bn254, Rep3AcvmType};
use co_ultrahonk::prelude::{HonkProof, ProverCrs};
use eyre::Context;
use mpc_core::protocols::rep3::{Rep3PrimeFieldShare, Rep3State};
use mpc_net::Network;
use noirc_artifacts::program::ProgramArtifact;
use oblivious_map_proof::{
    noir::{r1cs, ultrahonk},
    r1cs::noir_proof_schema::NoirProofScheme,
};

use super::Curve;
use super::F;

const NUM_TRANSACTION_COMMITMENTS: usize = 5;

impl<K> PrivateDeposit<K, DepositValueShare<F>>
where
    K: std::hash::Hash + Eq,
{
    fn get_transaction_input(
        sender_old: DepositValueShare<F>,
        receiver_old: Option<DepositValueShare<F>>,
        amount: Rep3PrimeFieldShare<F>,
        amount_blinding: Rep3PrimeFieldShare<F>,
        sender_new_blinding: Rep3PrimeFieldShare<F>,
        receiver_new_blinding: Rep3PrimeFieldShare<F>,
    ) -> (
        Vec<Rep3AcvmType<F>>,
        Rep3PrimeFieldShare<F>,
        Rep3PrimeFieldShare<F>,
    ) {
        let mut inputs = Vec::with_capacity(8);
        inputs.push(Rep3AcvmType::from(sender_old.amount));
        inputs.push(Rep3AcvmType::from(sender_old.blinding));
        let (reciever_old_amount, reciever_old_blinding) = if let Some(old) = receiver_old {
            inputs.push(Rep3AcvmType::from(old.amount));
            inputs.push(Rep3AcvmType::from(old.blinding));
            (old.amount, old.blinding)
        } else {
            inputs.push(Rep3AcvmType::from(F::zero()));
            inputs.push(Rep3AcvmType::from(F::zero()));
            (Rep3PrimeFieldShare::zero(), Rep3PrimeFieldShare::zero())
        };
        inputs.push(Rep3AcvmType::from(amount));
        inputs.push(Rep3AcvmType::from(amount_blinding));
        inputs.push(Rep3AcvmType::from(sender_new_blinding));
        inputs.push(Rep3AcvmType::from(receiver_new_blinding));
        (inputs, reciever_old_amount, reciever_old_blinding)
    }

    #[expect(clippy::too_many_arguments, clippy::type_complexity)]
    pub fn transaction_with_ultrahonk_proof<N: Network>(
        &mut self,
        sender_key: K,
        receiver_key: K,
        amount: Rep3PrimeFieldShare<F>,
        amount_blinding: Rep3PrimeFieldShare<F>, // For the commitment to the amount
        program_artifact: ProgramArtifact,
        constraint_system: &AcirFormat<F>,
        prover_crs: &ProverCrs<Bn254>,
        net0: &N,
        net1: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(
        DepositValueShare<F>,
        DepositValueShare<F>,
        HonkProof<F>,
        Vec<F>,
    )> {
        let (sender_old, sender_new, receiver_old, receiver_new) =
            self.transaction(sender_key, receiver_key, amount, rep3_state)?;

        let (inputs, reciever_old_amount, reciever_old_blinding) = Self::get_transaction_input(
            sender_old.to_owned(),
            receiver_old,
            amount,
            amount_blinding,
            sender_new.blinding,
            receiver_new.blinding,
        );

        // let witness = ultrahonk::conoir_witness_extension(inputs, program_artifact, net0, net1)?;
        let traces = super::poseidon2_commitment_helper::<NUM_TRANSACTION_COMMITMENTS, _, _, _>(
            [
                amount,
                amount_blinding,
                sender_old.amount,
                sender_old.blinding,
                sender_new.amount,
                sender_new.blinding,
                reciever_old_amount,
                reciever_old_blinding,
                receiver_new.amount,
                receiver_new.blinding,
            ],
            net0,
            rep3_state,
        )?;
        let witness = ultrahonk::r1cs_witness_extension_with_helper(
            inputs,
            traces,
            program_artifact,
            net0,
            net1,
        )?;

        let (proof, public_inputs) =
            ultrahonk::prove(constraint_system, witness, prover_crs, net0, net1)?;

        Ok((sender_new, receiver_new, proof, public_inputs))
    }

    #[expect(clippy::too_many_arguments, clippy::type_complexity)]
    pub fn transaction_with_groth16_proof<N: Network>(
        &mut self,
        sender_key: K,
        receiver_key: K,
        amount: Rep3PrimeFieldShare<F>,
        amount_blinding: Rep3PrimeFieldShare<F>, // For the commitment to the amount
        proof_schema: &NoirProofScheme<F>,
        cs: &ConstraintMatrices<F>,
        pk: &ProvingKey<Curve>,
        net0: &N,
        net1: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(
        DepositValueShare<F>,
        DepositValueShare<F>,
        Proof<Curve>,
        Vec<F>,
    )> {
        let (sender_old, sender_new, receiver_old, receiver_new) =
            self.transaction(sender_key, receiver_key, amount, rep3_state)?;

        let (inputs, reciever_old_amount, reciever_old_blinding) = Self::get_transaction_input(
            sender_old.to_owned(),
            receiver_old,
            amount,
            amount_blinding,
            sender_new.blinding,
            receiver_new.blinding,
        );

        let traces = super::poseidon2_commitment_helper::<NUM_TRANSACTION_COMMITMENTS, _, _, _>(
            [
                amount,
                amount_blinding,
                sender_old.amount,
                sender_old.blinding,
                sender_new.amount,
                sender_new.blinding,
                reciever_old_amount,
                reciever_old_blinding,
                receiver_new.amount,
                receiver_new.blinding,
            ],
            net0,
            rep3_state,
        )?;
        let r1cs =
            r1cs::trace_to_r1cs_witness(inputs, traces, proof_schema, net0, net1, rep3_state)
                .context("while translating witness to R1CS")
                .unwrap();

        let witness = r1cs::r1cs_witness_to_cogroth16(proof_schema, r1cs, rep3_state.id);

        let (proof, public_inputs) =
            r1cs::prove(cs, pk, witness, net0, net1).context("while generating Groth16 proof")?;

        Ok((sender_new, receiver_new, proof, public_inputs))
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
    fn transaction_ultrahonk_test() {
        // TestConfig::install_tracing();

        // Init Ultrahonk
        // Read constraint system and keys
        let pa = TestConfig::get_transaction_program_artifact().unwrap();
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
            let sender_key = TestConfig::get_random_map_key(&plain_map, &mut rng);
            // Either new key or existing key, with 50% probability each
            let receiver_key = if rng.r#gen::<bool>() {
                F::rand(&mut rng)
            } else {
                TestConfig::get_random_map_key(&plain_map, &mut rng)
            };
            let amount_blinding = F::rand(&mut rng);

            // Insert the sender (just the amount) into the plain map
            let sender_read_plain = plain_map.get(&sender_key).unwrap();
            let max_amount = sender_read_plain.amount.into_bigint().0[0];
            assert_eq!(F::from(max_amount), sender_read_plain.amount); // Debug Assert
            let amount = F::from(rng.gen_range(0..=max_amount));
            let sender_result_amount = sender_read_plain.amount - amount;
            plain_map.insert(
                sender_key,
                DepositValuePlain::new(sender_result_amount, F::zero()),
            );
            // Insert the receiver (just the amount) into the plain map
            let receiver_read_plain = plain_map.get(&receiver_key);
            let receiver_result_amount = if let Some(v) = receiver_read_plain {
                amount + v.amount
            } else {
                amount
            };
            plain_map.insert(
                receiver_key,
                DepositValuePlain::new(receiver_result_amount, F::zero()),
            );

            // Share the amount and the blinding
            let amount_share = rep3::share_field_element(amount, &mut rng);
            let amount_blinding_share = rep3::share_field_element(amount_blinding, &mut rng);

            // Do the MPC work
            let (sender_read, receiver_read, proof, public_inputs) = thread::scope(|scope| {
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

                        let (sender_read, receiver_read, proof, public_inputs) = map
                            .transaction_with_ultrahonk_proof(
                                sender_key,
                                receiver_key,
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

                        (sender_read, receiver_read, proof, public_inputs)
                    });
                    handles.push(handle);
                }

                let mut sender_read = Vec::with_capacity(handles.len());
                let mut receiver_read = Vec::with_capacity(handles.len());
                let (sender_read0, receiver_read0, proof0, public_inputs0) =
                    handles.remove(0).join().unwrap();
                sender_read.push(sender_read0.amount);
                receiver_read.push(receiver_read0.amount);
                for handle in handles {
                    let (sender_read_, receiver_read_, proof, public_inputs) =
                        handle.join().unwrap();
                    assert_eq!(proof, proof0);
                    assert_eq!(public_inputs, public_inputs0);
                    sender_read.push(sender_read_.amount);
                    receiver_read.push(receiver_read_.amount);
                }
                let sender_read =
                    rep3::combine_field_element(sender_read[0], sender_read[1], sender_read[2]);
                let receiver_read = rep3::combine_field_element(
                    receiver_read[0],
                    receiver_read[1],
                    receiver_read[2],
                );
                (sender_read, receiver_read, proof0, public_inputs0)
            });

            // Verifiy the results
            assert_eq!(sender_result_amount, sender_read);
            assert_eq!(receiver_result_amount, receiver_read);
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
    fn transaction_groth16_test() {
        // TestConfig::install_tracing();

        // Init Groth16
        // Read constraint system
        let pa = TestConfig::get_transaction_program_artifact().unwrap();

        // Get the R1CS proof schema
        let mut rng = rand::thread_rng();
        let (proof_schema, pk, cs) = r1cs::setup_r1cs(pa, &mut rng).unwrap();
        let proof_schema = Arc::new(proof_schema);
        let pk = Arc::new(pk);
        let cs = Arc::new(cs);

        // Init networks
        let mut test_network0 = LocalNetwork::new(3);
        let mut test_network1 = LocalNetwork::new(3);

        // Get a random map and its shares
        let mut plain_map =
            TestConfig::get_random_plain_map::<F, _>(TestConfig::NUM_ITEMS, &mut rng);
        let mut map_shares = plain_map.share(&mut rng);

        // The actual testcase
        for _ in 0..TestConfig::TEST_RUNS {
            let sender_key = TestConfig::get_random_map_key(&plain_map, &mut rng);
            // Either new key or existing key, with 50% probability each
            let receiver_key = if rng.r#gen::<bool>() {
                F::rand(&mut rng)
            } else {
                TestConfig::get_random_map_key(&plain_map, &mut rng)
            };
            let amount_blinding = F::rand(&mut rng);

            // Insert the sender (just the amount) into the plain map
            let sender_read_plain = plain_map.get(&sender_key).unwrap();
            let max_amount = sender_read_plain.amount.into_bigint().0[0];
            assert_eq!(F::from(max_amount), sender_read_plain.amount); // Debug Assert
            let amount = F::from(rng.gen_range(0..=max_amount));
            let sender_result_amount = sender_read_plain.amount - amount;
            plain_map.insert(
                sender_key,
                DepositValuePlain::new(sender_result_amount, F::zero()),
            );
            // Insert the receiver (just the amount) into the plain map
            let receiver_read_plain = plain_map.get(&receiver_key);
            let receiver_result_amount = if let Some(v) = receiver_read_plain {
                amount + v.amount
            } else {
                amount
            };
            plain_map.insert(
                receiver_key,
                DepositValuePlain::new(receiver_result_amount, F::zero()),
            );

            // Share the amount and the blinding
            let amount_share = rep3::share_field_element(amount, &mut rng);
            let amount_blinding_share = rep3::share_field_element(amount_blinding, &mut rng);

            // Do the MPC work
            let (sender_read, receiver_read, proof, public_inputs) = thread::scope(|scope| {
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

                        let (sender_read, receiver_read, proof, public_inputs) = map
                            .transaction_with_groth16_proof(
                                sender_key,
                                receiver_key,
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

                        (sender_read, receiver_read, proof, public_inputs)
                    });
                    handles.push(handle);
                }

                let mut sender_read = Vec::with_capacity(handles.len());
                let mut receiver_read = Vec::with_capacity(handles.len());
                let (sender_read0, receiver_read0, proof0, public_inputs0) =
                    handles.remove(0).join().unwrap();
                sender_read.push(sender_read0.amount);
                receiver_read.push(receiver_read0.amount);
                for handle in handles {
                    let (sender_read_, receiver_read_, proof, public_inputs) =
                        handle.join().unwrap();
                    assert_eq!(proof, proof0);
                    assert_eq!(public_inputs, public_inputs0);
                    sender_read.push(sender_read_.amount);
                    receiver_read.push(receiver_read_.amount);
                }
                let sender_read =
                    rep3::combine_field_element(sender_read[0], sender_read[1], sender_read[2]);
                let receiver_read = rep3::combine_field_element(
                    receiver_read[0],
                    receiver_read[1],
                    receiver_read[2],
                );
                (sender_read, receiver_read, proof0, public_inputs0)
            });

            // Verifiy the results
            assert_eq!(sender_result_amount, sender_read);
            assert_eq!(receiver_result_amount, receiver_read);
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
