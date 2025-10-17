use crate::{
    data_structure::{DepositValueShare, PrivateDeposit},
    proof::transaction::NUM_TRANSACTION_COMMITMENTS,
};
use ark_ff::{PrimeField, Zero};
use ark_groth16::Proof;
use co_circom::{ConstraintMatrices, ProvingKey, Rep3SharedWitness};
use co_noir::{AcirFormat, HonkProof, Rep3AcvmType};
use co_noir_common::crs::ProverCrs;
use co_noir_to_r1cs::{
    noir::{r1cs, ultrahonk},
    r1cs::noir_proof_schema::NoirProofScheme,
};
use eyre::Context;
use itertools::izip;
use mpc_core::protocols::rep3::{Rep3PrimeFieldShare, Rep3State};
use mpc_net::Network;
use noirc_artifacts::program::ProgramArtifact;
use rand::{CryptoRng, Rng};
use std::thread;

use super::Curve;
use super::F;

// From the Noir circuits
pub(super) const NUM_TRANSACTIONS: usize = 96;
pub(super) const NUM_COMMITMENTS: usize = NUM_TRANSACTIONS * NUM_TRANSACTION_COMMITMENTS;

#[derive(Clone, Debug, Default)]
pub struct TransactionInput<K, F> {
    pub sender_key: K,
    pub receiver_key: K,
    pub amount: F,
    pub amount_blinding: F,
}

impl<K, F: PrimeField> TransactionInput<K, F> {
    pub fn share<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> [TransactionInput<K, Rep3PrimeFieldShare<F>>; 3]
    where
        K: Clone,
    {
        let amount_shares = mpc_core::protocols::rep3::share_field_element(self.amount, rng);
        let amount_blinding_shares =
            mpc_core::protocols::rep3::share_field_element(self.amount_blinding, rng);
        [
            TransactionInput {
                sender_key: self.sender_key.clone(),
                receiver_key: self.receiver_key.clone(),
                amount: amount_shares[0],
                amount_blinding: amount_blinding_shares[0],
            },
            TransactionInput {
                sender_key: self.sender_key.clone(),
                receiver_key: self.receiver_key.clone(),
                amount: amount_shares[1],
                amount_blinding: amount_blinding_shares[1],
            },
            TransactionInput {
                sender_key: self.sender_key.clone(),
                receiver_key: self.receiver_key.clone(),
                amount: amount_shares[2],
                amount_blinding: amount_blinding_shares[2],
            },
        ]
    }
}

impl<K> PrivateDeposit<K, DepositValueShare<F>>
where
    K: std::hash::Hash + Eq + Clone + Send + Sync,
{
    fn add_to_tranasction_input(
        inputs: &mut Vec<Rep3AcvmType<F>>,
        sender_old: DepositValueShare<F>,
        receiver_old: Option<DepositValueShare<F>>,
        amount: Rep3PrimeFieldShare<F>,
        amount_blinding: Rep3PrimeFieldShare<F>,
        sender_new_blinding: Rep3PrimeFieldShare<F>,
        receiver_new_blinding: Rep3PrimeFieldShare<F>,
    ) -> (Rep3PrimeFieldShare<F>, Rep3PrimeFieldShare<F>) {
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
        (reciever_old_amount, reciever_old_blinding)
    }

    #[expect(clippy::type_complexity)]
    pub fn transaction_batched_with_commitments<N: Network>(
        &mut self,
        inputs: &[TransactionInput<K, Rep3PrimeFieldShare<F>>; NUM_TRANSACTIONS],
        net0: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(
        Vec<DepositValueShare<F>>,
        Vec<DepositValueShare<F>>,
        Vec<Rep3PrimeFieldShare<F>>,
    )> {
        let mut sender_new = Vec::with_capacity(NUM_TRANSACTIONS);
        let mut receiver_new = Vec::with_capacity(NUM_TRANSACTIONS);
        let mut commitment_inputs = [Rep3PrimeFieldShare::zero(); NUM_COMMITMENTS * 2]; // each commitment needs 2 inputs

        for (input, commitments) in inputs
            .iter()
            .zip(commitment_inputs.chunks_exact_mut(NUM_TRANSACTION_COMMITMENTS * 2))
        {
            let (sender_old, sender_new_, receiver_old, receiver_new_) = self.transaction(
                input.sender_key.clone(),
                input.receiver_key.clone(),
                input.amount,
                rep3_state,
            )?;

            let (reciever_old_amount, reciever_old_blinding) = if let Some(old) = receiver_old {
                (old.amount, old.blinding)
            } else {
                (Rep3PrimeFieldShare::zero(), Rep3PrimeFieldShare::zero())
            };

            commitments[0] = sender_old.amount;
            commitments[1] = sender_old.blinding;
            commitments[2] = sender_new_.amount;
            commitments[3] = sender_new_.blinding;
            commitments[4] = reciever_old_amount;
            commitments[5] = reciever_old_blinding;
            commitments[6] = receiver_new_.amount;
            commitments[7] = receiver_new_.blinding;
            commitments[8] = input.amount;
            commitments[9] = input.amount_blinding;

            sender_new.push(sender_new_);
            receiver_new.push(receiver_new_);
        }

        let commitments = super::poseidon2_commitments::<NUM_COMMITMENTS, _, _, _>(
            commitment_inputs,
            net0,
            rep3_state,
        )?;
        Ok((sender_new, receiver_new, commitments))
    }

    #[expect(clippy::type_complexity)]
    pub fn transaction_multithread_with_commitments<N: Network>(
        &mut self,
        inputs: &[TransactionInput<K, Rep3PrimeFieldShare<F>>; NUM_TRANSACTIONS],
        nets: &[N; NUM_TRANSACTIONS],
        rep3_states: &mut [Rep3State; NUM_TRANSACTIONS],
    ) -> eyre::Result<(
        Vec<DepositValueShare<F>>,
        Vec<DepositValueShare<F>>,
        Vec<Rep3PrimeFieldShare<F>>,
    )> {
        let mut sender_new = Vec::with_capacity(NUM_TRANSACTIONS);
        let mut receiver_new = Vec::with_capacity(NUM_TRANSACTIONS);
        let mut commitments = Vec::with_capacity(NUM_COMMITMENTS);

        let result = thread::scope(|scope| {
            let mut handles = Vec::with_capacity(3);
            for (input, net, rep3_state) in
                izip!(inputs.iter(), nets.iter(), rep3_states.iter_mut())
            {
                let (sender_old, sender_new, receiver_old, receiver_new) = self.transaction(
                    input.sender_key.to_owned(),
                    input.receiver_key.to_owned(),
                    input.amount,
                    rep3_state,
                )?;

                let handle = scope.spawn(move || {
                    let (reciever_old_amount, reciever_old_blinding) =
                        if let Some(old) = receiver_old {
                            (old.amount, old.blinding)
                        } else {
                            (Rep3PrimeFieldShare::zero(), Rep3PrimeFieldShare::zero())
                        };

                    let commitments =
                        super::poseidon2_commitments::<NUM_TRANSACTION_COMMITMENTS, _, _, _>(
                            [
                                sender_old.amount,
                                sender_old.blinding,
                                sender_new.amount,
                                sender_new.blinding,
                                reciever_old_amount,
                                reciever_old_blinding,
                                receiver_new.amount,
                                receiver_new.blinding,
                                input.amount,
                                input.amount_blinding,
                            ],
                            net,
                            rep3_state,
                        )?;

                    Result::<_, eyre::Report>::Ok((sender_new, receiver_new, commitments))
                });
                handles.push(handle);
            }
            for handle in handles {
                let (sender_new_, receiver_new_, commitments_) =
                    handle.join().map_err(|_| {
                        eyre::eyre!("A thread panicked while processing a transaction")
                    })??;
                sender_new.push(sender_new_);
                receiver_new.push(receiver_new_);
                commitments.extend(commitments_);
            }
            Result::<_, eyre::Report>::Ok(())
        });
        result?;

        Ok((sender_new, receiver_new, commitments))
    }

    #[expect(clippy::too_many_arguments, clippy::type_complexity)]
    pub fn transaction_batched_with_ultrahonk_proof<N: Network>(
        &mut self,
        inputs: &[TransactionInput<K, Rep3PrimeFieldShare<F>>; NUM_TRANSACTIONS],
        program_artifact: ProgramArtifact,
        constraint_system: &AcirFormat<F>,
        prover_crs: &ProverCrs<ark_bn254::G1Projective>,
        net0: &N,
        net1: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(
        Vec<DepositValueShare<F>>,
        Vec<DepositValueShare<F>>,
        HonkProof<F>,
        Vec<F>,
    )> {
        let mut sender_new = Vec::with_capacity(NUM_TRANSACTIONS);
        let mut receiver_new = Vec::with_capacity(NUM_TRANSACTIONS);
        let mut commitment_inputs = [Rep3PrimeFieldShare::zero(); NUM_COMMITMENTS * 2]; // each commitment needs 2 inputs
        let mut proof_inputs = Vec::with_capacity(NUM_TRANSACTIONS * 8);

        for (input, commitments) in inputs
            .iter()
            .zip(commitment_inputs.chunks_exact_mut(NUM_TRANSACTION_COMMITMENTS * 2))
        {
            let (sender_old, sender_new_, receiver_old, receiver_new_) = self.transaction(
                input.sender_key.clone(),
                input.receiver_key.clone(),
                input.amount,
                rep3_state,
            )?;

            let (reciever_old_amount, reciever_old_blinding) = Self::add_to_tranasction_input(
                &mut proof_inputs,
                sender_old.to_owned(),
                receiver_old,
                input.amount,
                input.amount_blinding,
                sender_new_.blinding,
                receiver_new_.blinding,
            );

            commitments[0] = input.amount;
            commitments[1] = input.amount_blinding;
            commitments[2] = sender_old.amount;
            commitments[3] = sender_old.blinding;
            commitments[4] = sender_new_.amount;
            commitments[5] = sender_new_.blinding;
            commitments[6] = reciever_old_amount;
            commitments[7] = reciever_old_blinding;
            commitments[8] = receiver_new_.amount;
            commitments[9] = receiver_new_.blinding;

            sender_new.push(sender_new_);
            receiver_new.push(receiver_new_);
        }

        // let witness_stack =
        //     ultrahonk::conoir_witness_extension(proof_inputs, program_artifact, net0, net1)?;
        let traces = super::poseidon2_commitment_helper::<NUM_COMMITMENTS, _, _, _>(
            commitment_inputs,
            net0,
            rep3_state,
        )?;
        let witness_stack = ultrahonk::r1cs_witness_extension_with_helper(
            proof_inputs,
            traces,
            program_artifact,
            net0,
            net1,
        )?;
        let witness = co_noir::witness_stack_to_vec_rep3(witness_stack);

        let (proof, public_inputs) =
            ultrahonk::prove(constraint_system, witness, prover_crs, net0, net1)?;

        Ok((sender_new, receiver_new, proof, public_inputs))
    }

    #[expect(clippy::type_complexity)]
    pub fn transaction_batched_with_r1cs_witext<N: Network>(
        &mut self,
        inputs: &[TransactionInput<K, Rep3PrimeFieldShare<F>>; NUM_TRANSACTIONS],
        proof_schema: &NoirProofScheme<F>,
        net0: &N,
        net1: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(
        Vec<DepositValueShare<F>>,
        Vec<DepositValueShare<F>>,
        Rep3SharedWitness<F>,
    )> {
        let mut sender_new = Vec::with_capacity(NUM_TRANSACTIONS);
        let mut receiver_new = Vec::with_capacity(NUM_TRANSACTIONS);
        let mut commitment_inputs = [Rep3PrimeFieldShare::zero(); NUM_COMMITMENTS * 2]; // each commitment needs 2 inputs
        let mut proof_inputs = Vec::with_capacity(NUM_TRANSACTIONS * 8);

        for (input, commitments) in inputs
            .iter()
            .zip(commitment_inputs.chunks_exact_mut(NUM_TRANSACTION_COMMITMENTS * 2))
        {
            let (sender_old, sender_new_, receiver_old, receiver_new_) = self.transaction(
                input.sender_key.clone(),
                input.receiver_key.clone(),
                input.amount,
                rep3_state,
            )?;

            let (reciever_old_amount, reciever_old_blinding) = Self::add_to_tranasction_input(
                &mut proof_inputs,
                sender_old.to_owned(),
                receiver_old,
                input.amount,
                input.amount_blinding,
                sender_new_.blinding,
                receiver_new_.blinding,
            );

            commitments[0] = input.amount;
            commitments[1] = input.amount_blinding;
            commitments[2] = sender_old.amount;
            commitments[3] = sender_old.blinding;
            commitments[4] = sender_new_.amount;
            commitments[5] = sender_new_.blinding;
            commitments[6] = reciever_old_amount;
            commitments[7] = reciever_old_blinding;
            commitments[8] = receiver_new_.amount;
            commitments[9] = receiver_new_.blinding;

            sender_new.push(sender_new_);
            receiver_new.push(receiver_new_);
        }

        let traces = super::poseidon2_commitment_helper::<NUM_COMMITMENTS, _, _, _>(
            commitment_inputs,
            net0,
            rep3_state,
        )?;

        let r1cs =
            r1cs::trace_to_r1cs_witness(proof_inputs, traces, proof_schema, net0, net1, rep3_state)
                .context("while translating witness to R1CS")?;

        let witness = r1cs::r1cs_witness_to_cogroth16(proof_schema, r1cs, rep3_state.id);

        Ok((sender_new, receiver_new, witness))
    }

    #[expect(clippy::too_many_arguments, clippy::type_complexity)]
    pub fn transaction_batched_with_groth16_proof<N: Network>(
        &mut self,
        inputs: &[TransactionInput<K, Rep3PrimeFieldShare<F>>; NUM_TRANSACTIONS],
        proof_schema: &NoirProofScheme<F>,
        cs: &ConstraintMatrices<F>,
        pk: &ProvingKey<Curve>,
        net0: &N,
        net1: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(
        Vec<DepositValueShare<F>>,
        Vec<DepositValueShare<F>>,
        Proof<Curve>,
        Vec<F>,
    )> {
        let (sender_new, receiver_new, witness) = self.transaction_batched_with_r1cs_witext(
            inputs,
            proof_schema,
            net0,
            net1,
            rep3_state,
        )?;

        let (proof, public_inputs) =
            r1cs::prove(cs, pk, witness, net0, net1).context("while generating Groth16 proof")?;

        Ok((sender_new, receiver_new, proof, public_inputs))
    }

    #[expect(clippy::type_complexity)]
    pub fn transaction_multithread_with_r1cs_witext<N: Network>(
        &mut self,
        inputs: &[TransactionInput<K, Rep3PrimeFieldShare<F>>; NUM_TRANSACTIONS],
        proof_schema: &NoirProofScheme<F>,
        nets: &[N; NUM_TRANSACTIONS * 2],
        rep3_states: &mut [Rep3State; NUM_TRANSACTIONS],
    ) -> eyre::Result<(
        Vec<DepositValueShare<F>>,
        Vec<DepositValueShare<F>>,
        Rep3SharedWitness<F>,
    )> {
        let mut sender_new = Vec::with_capacity(NUM_TRANSACTIONS);
        let mut receiver_new = Vec::with_capacity(NUM_TRANSACTIONS);
        let mut proof_inputs = Vec::with_capacity(NUM_TRANSACTIONS * 8);
        let mut traces = Vec::with_capacity(NUM_COMMITMENTS);
        // The compiler groups bitdecomps by bits, so we have to store both used ones separately first
        let mut bitdecomps1 = Vec::with_capacity(NUM_TRANSACTIONS * 2);
        let mut bitdecomps2 = Vec::with_capacity(NUM_TRANSACTIONS);

        let result = thread::scope(|scope| {
            let mut handles = Vec::with_capacity(3);
            for (input, nets, rep3_state) in
                izip!(inputs.iter(), nets.chunks_exact(2), rep3_states.iter_mut())
            {
                let (sender_old, sender_new, receiver_old, receiver_new) = self.transaction(
                    input.sender_key.to_owned(),
                    input.receiver_key.to_owned(),
                    input.amount,
                    rep3_state,
                )?;

                let handle = scope.spawn(move || {
                    let (inputs, reciever_old_amount, reciever_old_blinding) =
                        Self::get_transaction_input(
                            sender_old.to_owned(),
                            receiver_old,
                            input.amount,
                            input.amount_blinding,
                            sender_new.blinding,
                            receiver_new.blinding,
                        );

                    // The poseidon2 traces
                    let traces =
                        super::poseidon2_commitment_helper::<NUM_TRANSACTION_COMMITMENTS, _, _, _>(
                            [
                                input.amount,
                                input.amount_blinding,
                                sender_old.amount,
                                sender_old.blinding,
                                sender_new.amount,
                                sender_new.blinding,
                                reciever_old_amount,
                                reciever_old_blinding,
                                receiver_new.amount,
                                receiver_new.blinding,
                            ],
                            &nets[0],
                            rep3_state,
                        )?;

                    // The bit decompositions
                    let (decomp_amount, decomp_sender) = super::decompose_compose_for_transaction(
                        input.amount,
                        sender_new.amount,
                        &nets[0],
                        &nets[1],
                        rep3_state,
                    )?;

                    Result::<_, eyre::Report>::Ok((
                        sender_new,
                        receiver_new,
                        inputs,
                        traces,
                        decomp_amount,
                        decomp_sender,
                    ))
                });
                handles.push(handle);
            }
            for handle in handles {
                let (sender_new_, receiver_new_, inputs_, traces_, decomps1, decomps2) =
                    handle.join().map_err(|_| {
                        eyre::eyre!("A thread panicked while processing a transaction")
                    })??;
                sender_new.push(sender_new_);
                receiver_new.push(receiver_new_);
                proof_inputs.extend(inputs_);
                traces.extend(traces_);
                bitdecomps1.extend(decomps1);
                bitdecomps2.extend(decomps2);
            }
            Result::<_, eyre::Report>::Ok(())
        });
        result?;

        bitdecomps1.extend(bitdecomps2);
        let bitdecomps = bitdecomps1;

        let r1cs = r1cs::trace_to_r1cs_witness_with_bitdecomp_witness(
            proof_inputs,
            traces,
            bitdecomps,
            proof_schema,
            &nets[0],
            &nets[1],
            &mut rep3_states[0],
        )
        .context("while translating witness to R1CS")?;

        let witness = r1cs::r1cs_witness_to_cogroth16(proof_schema, r1cs, rep3_states[0].id);

        Ok((sender_new, receiver_new, witness))
    }

    #[expect(clippy::type_complexity)]
    pub fn transaction_multithread_with_groth16_proof<N: Network>(
        &mut self,
        inputs: &[TransactionInput<K, Rep3PrimeFieldShare<F>>; NUM_TRANSACTIONS],
        proof_schema: &NoirProofScheme<F>,
        cs: &ConstraintMatrices<F>,
        pk: &ProvingKey<Curve>,
        nets: &[N; NUM_TRANSACTIONS * 2],
        rep3_states: &mut [Rep3State; NUM_TRANSACTIONS],
    ) -> eyre::Result<(
        Vec<DepositValueShare<F>>,
        Vec<DepositValueShare<F>>,
        Proof<Curve>,
        Vec<F>,
    )> {
        let (sender_new, receiver_new, witness) =
            self.transaction_multithread_with_r1cs_witext(inputs, proof_schema, nets, rep3_states)?;

        let (proof, public_inputs) = r1cs::prove(cs, pk, witness, &nets[0], &nets[1])
            .context("while generating Groth16 proof")?;

        Ok((sender_new, receiver_new, proof, public_inputs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{data_structure::DepositValuePlain, proof::TestConfig};
    use ark_ff::{UniformRand, Zero};
    use itertools::izip;
    use mpc_core::protocols::rep3::{self, Rep3State, conversion::A2BType};
    use mpc_net::local::LocalNetwork;
    use std::{array, sync::Arc, thread};

    #[test]
    #[ignore = "UltraHonk tests are ignored at the moment"]
    fn transaction_batched_ultrahonk_test() {
        // TestConfig::install_tracing();

        // Init Ultrahonk
        // Read constraint system and keys
        let pa = TestConfig::get_transaction_batched_program_artifact().unwrap();
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
        let num_items = std::cmp::min(
            TestConfig::NUM_ITEMS,
            NUM_TRANSACTIONS + (NUM_TRANSACTIONS >> 1),
        ); // We need at least NUM_TRANSACTIONS items to make sure we can always find a disjoint set of senders and NUM_TRANSACTIONS / 2 receivers. The remaining receivers are new
        let mut rng = rand::thread_rng();
        let mut plain_map = TestConfig::get_random_plain_map::<F, _>(num_items, &mut rng);
        let mut map_shares = plain_map.share(&mut rng);

        // The actual testcase
        for _ in 0..TestConfig::TEST_RUNS {
            // We make a disjoint set of senders and receivers
            let mut transaction_inputs: [TransactionInput<F, F>; NUM_TRANSACTIONS] =
                array::from_fn(|_| TransactionInput::default());
            {
                let mut plain_map_keys_iter = plain_map.keys();

                for (i, input) in transaction_inputs.iter_mut().enumerate() {
                    let sender_key = plain_map_keys_iter
                        .next()
                        .expect("Made sure we have enough items");
                    input.sender_key = *sender_key;

                    input.receiver_key = if i >= (NUM_TRANSACTIONS >> 1) {
                        F::rand(&mut rng)
                    } else {
                        let receiver_key = plain_map_keys_iter
                            .next()
                            .expect("Made sure we have enough items");
                        *receiver_key
                    };

                    input.amount_blinding = F::rand(&mut rng);
                }
            }

            let mut sender_result_amounts = Vec::with_capacity(NUM_TRANSACTIONS);
            let mut receiver_result_amounts = Vec::with_capacity(NUM_TRANSACTIONS);
            for input in transaction_inputs.iter_mut() {
                // Insert the sender (just the amount) into the plain map
                let sender_read_plain = plain_map.get(&input.sender_key).unwrap();
                let max_amount = sender_read_plain.amount.into_bigint().0[0];
                assert_eq!(F::from(max_amount), sender_read_plain.amount); // Debug Assert
                let amount = F::from(rng.gen_range(0..=max_amount));
                input.amount = amount;
                let sender_result_amount = sender_read_plain.amount - amount;
                plain_map.insert(
                    input.sender_key,
                    DepositValuePlain::new(sender_result_amount, F::zero()),
                );

                // Insert the receiver (just the amount) into the plain map
                let receiver_read_plain = plain_map.get(&input.receiver_key);
                let receiver_result_amount = if let Some(v) = receiver_read_plain {
                    amount + v.amount
                } else {
                    amount
                };
                plain_map.insert(
                    input.receiver_key,
                    DepositValuePlain::new(receiver_result_amount, F::zero()),
                );
                sender_result_amounts.push(sender_result_amount);
                receiver_result_amounts.push(receiver_result_amount);
            }

            // Share the amount and the blinding
            let mut shares = [
                Vec::with_capacity(NUM_TRANSACTIONS),
                Vec::with_capacity(NUM_TRANSACTIONS),
                Vec::with_capacity(NUM_TRANSACTIONS),
            ];
            for input in transaction_inputs {
                let [s0, s1, s2] = input.share(&mut rng);
                shares[0].push(s0);
                shares[1].push(s1);
                shares[2].push(s2);
            }

            // Do the MPC work
            let (sender_read, receiver_read, proof, public_inputs) = thread::scope(|scope| {
                let mut handles = Vec::with_capacity(3);
                for (net0, net1, map, transaction) in izip!(
                    &mut test_network0,
                    &mut test_network1,
                    &mut map_shares,
                    shares
                ) {
                    let constraint_system = constraint_system.clone();
                    let pa = pa.clone();
                    let prover_crs = prover_crs.clone();

                    let handle = scope.spawn(move || {
                        let mut rep3 = Rep3State::new(net0, A2BType::default()).unwrap();

                        let (sender_read, receiver_read, proof, public_inputs) = map
                            .transaction_batched_with_ultrahonk_proof(
                                transaction.as_slice().try_into().unwrap(),
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
                sender_read.push(
                    sender_read0
                        .into_iter()
                        .map(|v| v.amount)
                        .collect::<Vec<_>>(),
                );
                receiver_read.push(
                    receiver_read0
                        .into_iter()
                        .map(|v| v.amount)
                        .collect::<Vec<_>>(),
                );
                for handle in handles {
                    let (sender_read_, receiver_read_, proof, public_inputs) =
                        handle.join().unwrap();
                    assert_eq!(proof, proof0);
                    assert_eq!(public_inputs, public_inputs0);
                    sender_read.push(
                        sender_read_
                            .into_iter()
                            .map(|v| v.amount)
                            .collect::<Vec<_>>(),
                    );
                    receiver_read.push(
                        receiver_read_
                            .into_iter()
                            .map(|v| v.amount)
                            .collect::<Vec<_>>(),
                    );
                }
                let sender_read =
                    rep3::combine_field_elements(&sender_read[0], &sender_read[1], &sender_read[2]);
                let receiver_read = rep3::combine_field_elements(
                    &receiver_read[0],
                    &receiver_read[1],
                    &receiver_read[2],
                );
                (sender_read, receiver_read, proof0, public_inputs0)
            });

            // Verifiy the results
            assert_eq!(sender_result_amounts, sender_read);
            assert_eq!(receiver_result_amounts, receiver_read);
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
    #[ignore = "This test is slow in debug mode"]
    fn transaction_batched_groth16_test() {
        // TestConfig::install_tracing();

        // Init Groth16
        // Read constraint system
        let pa = TestConfig::get_transaction_batched_program_artifact().unwrap();

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
        let num_items = std::cmp::min(
            TestConfig::NUM_ITEMS,
            NUM_TRANSACTIONS + (NUM_TRANSACTIONS >> 1),
        ); // We need at least NUM_TRANSACTIONS items to make sure we can always find a disjoint set of senders and NUM_TRANSACTIONS / 2 receivers. The remaining receivers are new
        let mut rng = rand::thread_rng();
        let mut plain_map = TestConfig::get_random_plain_map::<F, _>(num_items, &mut rng);
        let mut map_shares = plain_map.share(&mut rng);

        // The actual testcase
        for _ in 0..TestConfig::TEST_RUNS {
            // We make a disjoint set of senders and receivers
            let mut transaction_inputs: [TransactionInput<F, F>; NUM_TRANSACTIONS] =
                array::from_fn(|_| TransactionInput::default());
            {
                let mut plain_map_keys_iter = plain_map.keys();

                for (i, input) in transaction_inputs.iter_mut().enumerate() {
                    let sender_key = plain_map_keys_iter
                        .next()
                        .expect("Made sure we have enough items");
                    input.sender_key = *sender_key;

                    input.receiver_key = if i >= (NUM_TRANSACTIONS >> 1) {
                        F::rand(&mut rng)
                    } else {
                        let receiver_key = plain_map_keys_iter
                            .next()
                            .expect("Made sure we have enough items");
                        *receiver_key
                    };

                    input.amount_blinding = F::rand(&mut rng);
                }
            }

            let mut sender_result_amounts = Vec::with_capacity(NUM_TRANSACTIONS);
            let mut receiver_result_amounts = Vec::with_capacity(NUM_TRANSACTIONS);
            for input in transaction_inputs.iter_mut() {
                // Insert the sender (just the amount) into the plain map
                let sender_read_plain = plain_map.get(&input.sender_key).unwrap();
                let max_amount = sender_read_plain.amount.into_bigint().0[0];
                assert_eq!(F::from(max_amount), sender_read_plain.amount); // Debug Assert
                let amount = F::from(rng.gen_range(0..=max_amount));
                input.amount = amount;
                let sender_result_amount = sender_read_plain.amount - amount;
                plain_map.insert(
                    input.sender_key,
                    DepositValuePlain::new(sender_result_amount, F::zero()),
                );

                // Insert the receiver (just the amount) into the plain map
                let receiver_read_plain = plain_map.get(&input.receiver_key);
                let receiver_result_amount = if let Some(v) = receiver_read_plain {
                    amount + v.amount
                } else {
                    amount
                };
                plain_map.insert(
                    input.receiver_key,
                    DepositValuePlain::new(receiver_result_amount, F::zero()),
                );
                sender_result_amounts.push(sender_result_amount);
                receiver_result_amounts.push(receiver_result_amount);
            }

            // Share the amount and the blinding
            let mut shares = [
                Vec::with_capacity(NUM_TRANSACTIONS),
                Vec::with_capacity(NUM_TRANSACTIONS),
                Vec::with_capacity(NUM_TRANSACTIONS),
            ];
            for input in transaction_inputs {
                let [s0, s1, s2] = input.share(&mut rng);
                shares[0].push(s0);
                shares[1].push(s1);
                shares[2].push(s2);
            }

            // Do the MPC work
            let (sender_read, receiver_read, proof, public_inputs) = thread::scope(|scope| {
                let mut handles = Vec::with_capacity(3);
                for (net0, net1, map, transaction) in izip!(
                    &mut test_network0,
                    &mut test_network1,
                    &mut map_shares,
                    shares
                ) {
                    let proof_schema = proof_schema.clone();
                    let cs = cs.clone();
                    let pk = pk.clone();
                    let handle = scope.spawn(move || {
                        let mut rep3 = Rep3State::new(net0, A2BType::default()).unwrap();

                        let (sender_read, receiver_read, proof, public_inputs) = map
                            .transaction_batched_with_groth16_proof(
                                transaction.as_slice().try_into().unwrap(),
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
                sender_read.push(
                    sender_read0
                        .into_iter()
                        .map(|v| v.amount)
                        .collect::<Vec<_>>(),
                );
                receiver_read.push(
                    receiver_read0
                        .into_iter()
                        .map(|v| v.amount)
                        .collect::<Vec<_>>(),
                );
                for handle in handles {
                    let (sender_read_, receiver_read_, proof, public_inputs) =
                        handle.join().unwrap();
                    assert_eq!(proof, proof0);
                    assert_eq!(public_inputs, public_inputs0);
                    sender_read.push(
                        sender_read_
                            .into_iter()
                            .map(|v| v.amount)
                            .collect::<Vec<_>>(),
                    );
                    receiver_read.push(
                        receiver_read_
                            .into_iter()
                            .map(|v| v.amount)
                            .collect::<Vec<_>>(),
                    );
                }
                let sender_read =
                    rep3::combine_field_elements(&sender_read[0], &sender_read[1], &sender_read[2]);
                let receiver_read = rep3::combine_field_elements(
                    &receiver_read[0],
                    &receiver_read[1],
                    &receiver_read[2],
                );
                (sender_read, receiver_read, proof0, public_inputs0)
            });

            // Verifiy the results
            assert_eq!(sender_result_amounts, sender_read);
            assert_eq!(receiver_result_amounts, receiver_read);
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

    #[test]
    #[ignore = "This test is slow in debug mode"]
    fn transaction_multithread_groth16_test() {
        // TestConfig::install_tracing();

        // Init Groth16
        // Read constraint system
        let pa = TestConfig::get_transaction_batched_program_artifact().unwrap();

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
        let mut test_networks0 = Vec::with_capacity(NUM_TRANSACTIONS * 2);
        let mut test_networks1 = Vec::with_capacity(NUM_TRANSACTIONS * 2);
        let mut test_networks2 = Vec::with_capacity(NUM_TRANSACTIONS);
        for _ in 0..(NUM_TRANSACTIONS * 2) {
            let [net0, net1, net2] = LocalNetwork::new(3).try_into().unwrap();
            test_networks0.push(net0);
            test_networks1.push(net1);
            test_networks2.push(net2);
        }

        // Get a random map and its shares
        let num_items = std::cmp::min(
            TestConfig::NUM_ITEMS,
            NUM_TRANSACTIONS + (NUM_TRANSACTIONS >> 1),
        ); // We need at least NUM_TRANSACTIONS items to make sure we can always find a disjoint set of senders and NUM_TRANSACTIONS / 2 receivers. The remaining receivers are new
        let mut rng = rand::thread_rng();
        let mut plain_map = TestConfig::get_random_plain_map::<F, _>(num_items, &mut rng);
        let mut map_shares = plain_map.share(&mut rng);

        // The actual testcase
        for _ in 0..TestConfig::TEST_RUNS {
            // We make a disjoint set of senders and receivers
            let mut transaction_inputs: [TransactionInput<F, F>; NUM_TRANSACTIONS] =
                array::from_fn(|_| TransactionInput::default());
            {
                let mut plain_map_keys_iter = plain_map.keys();

                for (i, input) in transaction_inputs.iter_mut().enumerate() {
                    let sender_key = plain_map_keys_iter
                        .next()
                        .expect("Made sure we have enough items");
                    input.sender_key = *sender_key;

                    input.receiver_key = if i >= (NUM_TRANSACTIONS >> 1) {
                        F::rand(&mut rng)
                    } else {
                        let receiver_key = plain_map_keys_iter
                            .next()
                            .expect("Made sure we have enough items");
                        *receiver_key
                    };

                    input.amount_blinding = F::rand(&mut rng);
                }
            }

            let mut sender_result_amounts = Vec::with_capacity(NUM_TRANSACTIONS);
            let mut receiver_result_amounts = Vec::with_capacity(NUM_TRANSACTIONS);
            for input in transaction_inputs.iter_mut() {
                // Insert the sender (just the amount) into the plain map
                let sender_read_plain = plain_map.get(&input.sender_key).unwrap();
                let max_amount = sender_read_plain.amount.into_bigint().0[0];
                assert_eq!(F::from(max_amount), sender_read_plain.amount); // Debug Assert
                let amount = F::from(rng.gen_range(0..=max_amount));
                input.amount = amount;
                let sender_result_amount = sender_read_plain.amount - amount;
                plain_map.insert(
                    input.sender_key,
                    DepositValuePlain::new(sender_result_amount, F::zero()),
                );

                // Insert the receiver (just the amount) into the plain map
                let receiver_read_plain = plain_map.get(&input.receiver_key);
                let receiver_result_amount = if let Some(v) = receiver_read_plain {
                    amount + v.amount
                } else {
                    amount
                };
                plain_map.insert(
                    input.receiver_key,
                    DepositValuePlain::new(receiver_result_amount, F::zero()),
                );
                sender_result_amounts.push(sender_result_amount);
                receiver_result_amounts.push(receiver_result_amount);
            }

            // Share the amount and the blinding
            let mut shares = [
                Vec::with_capacity(NUM_TRANSACTIONS),
                Vec::with_capacity(NUM_TRANSACTIONS),
                Vec::with_capacity(NUM_TRANSACTIONS),
            ];
            for input in transaction_inputs {
                let [s0, s1, s2] = input.share(&mut rng);
                shares[0].push(s0);
                shares[1].push(s1);
                shares[2].push(s2);
            }

            // Do the MPC work
            let (sender_read, receiver_read, proof, public_inputs) = thread::scope(|scope| {
                let mut handles = Vec::with_capacity(3);
                for (nets, map, transaction) in izip!(
                    [
                        &mut test_networks0,
                        &mut test_networks1,
                        &mut test_networks2
                    ],
                    &mut map_shares,
                    shares
                ) {
                    let proof_schema = proof_schema.clone();
                    let cs = cs.clone();
                    let pk = pk.clone();
                    let handle = scope.spawn(move || {
                        let mut rep3_states = Vec::with_capacity(nets.len() / 2);
                        for net in nets.iter().take(nets.len() / 2) {
                            rep3_states.push(Rep3State::new(net, A2BType::default()).unwrap());
                        }

                        let (sender_read, receiver_read, proof, public_inputs) = map
                            .transaction_multithread_with_groth16_proof(
                                transaction.as_slice().try_into().unwrap(),
                                &proof_schema,
                                &cs,
                                &pk,
                                nets.as_slice().try_into().unwrap(),
                                rep3_states.as_mut_slice().try_into().unwrap(),
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
                sender_read.push(
                    sender_read0
                        .into_iter()
                        .map(|v| v.amount)
                        .collect::<Vec<_>>(),
                );
                receiver_read.push(
                    receiver_read0
                        .into_iter()
                        .map(|v| v.amount)
                        .collect::<Vec<_>>(),
                );
                for handle in handles {
                    let (sender_read_, receiver_read_, proof, public_inputs) =
                        handle.join().unwrap();
                    assert_eq!(proof, proof0);
                    assert_eq!(public_inputs, public_inputs0);
                    sender_read.push(
                        sender_read_
                            .into_iter()
                            .map(|v| v.amount)
                            .collect::<Vec<_>>(),
                    );
                    receiver_read.push(
                        receiver_read_
                            .into_iter()
                            .map(|v| v.amount)
                            .collect::<Vec<_>>(),
                    );
                }
                let sender_read =
                    rep3::combine_field_elements(&sender_read[0], &sender_read[1], &sender_read[2]);
                let receiver_read = rep3::combine_field_elements(
                    &receiver_read[0],
                    &receiver_read[1],
                    &receiver_read[2],
                );
                (sender_read, receiver_read, proof0, public_inputs0)
            });

            // Verifiy the results
            assert_eq!(sender_result_amounts, sender_read);
            assert_eq!(receiver_result_amounts, receiver_read);
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
