use crate::data_structure::{DepositValueShare, PrivateDeposit};
use crate::proof::NUM_WITHDRAW_NEW_BITS;
use crate::proof::transaction::NUM_TRANSACTION_COMMITMENTS;
use crate::proof::transaction_batched::{NUM_COMMITMENTS, NUM_TRANSACTIONS};
use ark_ff::Zero;
use ark_groth16::Proof;
use co_circom::{ConstraintMatrices, ProvingKey, Rep3SharedWitness};
use co_noir::Rep3AcvmType;
use co_noir_common::utils::Utils;
use co_noir_to_r1cs::{noir::r1cs, r1cs::noir_proof_schema::NoirProofScheme};
use eyre::Context;
use itertools::izip;
use mpc_core::protocols::rep3::id::PartyID;
use mpc_core::protocols::rep3::{self, Rep3PrimeFieldShare, Rep3State};
use mpc_core::protocols::rep3_ring::ring::bit::Bit;
use mpc_core::protocols::rep3_ring::{self, Rep3RingShare};
use mpc_net::Network;
use std::thread;

use super::Curve;
use super::F;

pub enum Action<K> {
    Invalid,
    Deposit(K, F),                                                  // Receiver, amount
    Withdraw(K, F),                                                 // Sender, amount
    Transfer(K, K, Rep3PrimeFieldShare<F>, Rep3PrimeFieldShare<F>), // Sender, Receiver, amount, amount_blinding
    Dummy,
}

impl<K> PrivateDeposit<K, DepositValueShare<F>>
where
    K: std::hash::Hash + Eq + Clone + Send + Sync,
{
    pub fn zero_commitment() -> F {
        Utils::field_from_hex_string(
            "0x87f763a403ee4109adc79d4a7638af3cb8cb6a33f5b027bd1476ffa97361acb",
        )
        .expect("Knwon string should work") // commit(0, 0)
    }

    #[expect(clippy::type_complexity, clippy::too_many_arguments)]
    pub fn process_transaction<N: Network>(
        sender_old: DepositValueShare<F>,
        receiver_old: Option<DepositValueShare<F>>,
        sender_new: DepositValueShare<F>,
        receiver_new: DepositValueShare<F>,
        amount: Rep3PrimeFieldShare<F>,
        amount_blinding: Rep3PrimeFieldShare<F>,
        net0: &N,
        net1: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(
        DepositValueShare<F>,
        DepositValueShare<F>,
        Vec<Rep3AcvmType<F>>,
        Vec<Vec<Rep3AcvmType<F>>>,
        Vec<Rep3PrimeFieldShare<F>>,
        Vec<Rep3PrimeFieldShare<F>>,
    )> {
        let (inputs, reciever_old_amount, reciever_old_blinding) = Self::get_transaction_input(
            sender_old.to_owned(),
            receiver_old,
            amount,
            amount_blinding,
            sender_new.blinding,
            receiver_new.blinding,
        );

        // The poseidon2 traces
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

        // The bit decompositions
        let (decomp_amount, decomp_sender) = super::decompose_compose_for_transaction(
            amount,
            sender_new.amount,
            net0,
            net1,
            rep3_state,
        )?;

        Ok((
            sender_new,
            receiver_new,
            inputs,
            traces,
            decomp_amount,
            decomp_sender,
        ))
    }

    fn get_deposit_input_public_amount(
        receiver_old: Option<DepositValueShare<F>>,
        amount: F,
        amount_blinding: F,
        receiver_new_blinding: Rep3PrimeFieldShare<F>,
    ) -> (
        Vec<Rep3AcvmType<F>>,
        Rep3PrimeFieldShare<F>,
        Rep3PrimeFieldShare<F>,
    ) {
        let mut inputs = Vec::with_capacity(8);
        inputs.push(Rep3AcvmType::from(amount));
        inputs.push(Rep3AcvmType::from(amount_blinding));
        let (old_amount, old_blinding) = if let Some(old) = receiver_old {
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
        inputs.push(Rep3AcvmType::from(F::zero()));
        inputs.push(Rep3AcvmType::from(receiver_new_blinding));
        (inputs, old_amount, old_blinding)
    }

    #[expect(clippy::type_complexity)]
    pub fn process_deposit<N: Network>(
        receiver_old: Option<DepositValueShare<F>>,
        receiver_new: DepositValueShare<F>,
        amount: F,
        net0: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(
        DepositValueShare<F>,
        DepositValueShare<F>,
        Vec<Rep3AcvmType<F>>,
        Vec<Vec<Rep3AcvmType<F>>>,
        Vec<Rep3PrimeFieldShare<F>>,
        Vec<Rep3PrimeFieldShare<F>>,
    )> {
        // let my_id = PartyID::try_from(net0.id())?;

        let (inputs, receiver_old_amount, receiver_old_blinding) =
            Self::get_deposit_input_public_amount(
                receiver_old,
                amount,
                F::zero(),
                receiver_new.blinding,
            );

        let sender_new = DepositValueShare::new(
            Rep3PrimeFieldShare::zero_share(),
            Rep3PrimeFieldShare::zero_share(),
        );

        let mut traces = super::poseidon2_commitment_helper::<2, _, _, _>(
            [
                receiver_old_amount,
                receiver_old_blinding,
                receiver_new.amount,
                receiver_new.blinding,
            ],
            net0,
            rep3_state,
        )?;

        let plain_traces = super::poseidon2_plain_commitment_helper::<2, _, _>([
            amount,
            F::zero(),
            F::zero(),
            F::zero(),
        ]);
        traces.insert(0, plain_traces[0].clone());
        traces.insert(0, plain_traces[0].clone());
        traces.insert(2, plain_traces[1].clone());

        // Elements are public, so we do not need bit decomposition witnesses
        let decomp_amount = vec![];
        let decomp_sender = vec![];

        Ok((
            sender_new,
            receiver_new,
            inputs,
            traces,
            decomp_amount,
            decomp_sender,
        ))
    }

    fn get_withdraw_input_public_amount(
        sender_old: DepositValueShare<F>,
        amount: F,
        amount_blinding: F,
        sender_new_blinding: Rep3PrimeFieldShare<F>,
    ) -> Vec<Rep3AcvmType<F>> {
        vec![
            Rep3AcvmType::from(sender_old.amount),
            Rep3AcvmType::from(sender_old.blinding),
            Rep3AcvmType::from(F::zero()),
            Rep3AcvmType::from(F::zero()),
            Rep3AcvmType::from(amount),
            Rep3AcvmType::from(amount_blinding),
            Rep3AcvmType::from(sender_new_blinding),
            Rep3AcvmType::from(F::zero()),
        ]
    }

    #[expect(clippy::assertions_on_constants)]
    pub(super) fn decompose_compose_for_withdraw<N: Network>(
        sender_new: Rep3PrimeFieldShare<F>,
        net0: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
        let a2b_sender = rep3::conversion::a2y2b(sender_new, net0, rep3_state)?;

        let mut to_compose = Vec::with_capacity(NUM_WITHDRAW_NEW_BITS);
        assert!(NUM_WITHDRAW_NEW_BITS <= 128);
        assert!(NUM_WITHDRAW_NEW_BITS > 64);
        let a2b_sender_a = a2b_sender.a.to_u64_digits();
        let a2b_sender_b = a2b_sender.b.to_u64_digits();
        let mut a2b_sender_a = ((a2b_sender_a[1] as u128) << 64) | a2b_sender_a[0] as u128;
        let mut a2b_sender_b = ((a2b_sender_b[1] as u128) << 64) | a2b_sender_b[0] as u128;
        for _ in 0..NUM_WITHDRAW_NEW_BITS {
            let bit = Rep3RingShare::new(
                Bit::new((a2b_sender_a & 1) == 1),
                Bit::new((a2b_sender_b & 1) == 1),
            );
            to_compose.push(bit);
            a2b_sender_a >>= 1;
            a2b_sender_b >>= 1;
        }
        let composed = rep3_ring::conversion::bit_inject_from_bits_to_field_many(
            &to_compose,
            net0,
            rep3_state,
        )?;

        Ok(composed)
    }

    #[expect(clippy::type_complexity)]
    pub fn process_withdraw<N: Network>(
        sender_old: DepositValueShare<F>,
        sender_new: DepositValueShare<F>,
        amount: F,
        net0: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(
        DepositValueShare<F>,
        DepositValueShare<F>,
        Vec<Rep3AcvmType<F>>,
        Vec<Vec<Rep3AcvmType<F>>>,
        Vec<Rep3PrimeFieldShare<F>>,
        Vec<Rep3PrimeFieldShare<F>>,
    )> {
        let my_id = PartyID::try_from(net0.id())?;

        let inputs = Self::get_withdraw_input_public_amount(
            sender_old.to_owned(),
            amount,
            F::zero(),
            sender_new.blinding,
        );

        let receiver_new = DepositValueShare::new(
            rep3::arithmetic::promote_to_trivial_share(my_id, amount),
            Rep3PrimeFieldShare::zero_share(),
        );

        let mut traces = super::poseidon2_commitment_helper::<2, _, _, _>(
            [
                sender_old.amount,
                sender_old.blinding,
                sender_new.amount,
                sender_new.blinding,
            ],
            net0,
            rep3_state,
        )?;

        let plain_traces = super::poseidon2_plain_commitment_helper::<2, _, _>([
            amount,
            F::zero(),
            F::zero(),
            F::zero(),
        ]);
        traces.insert(0, plain_traces[0].clone());
        traces.push(plain_traces[1].clone());
        traces.push(plain_traces[0].clone());

        // The bit decomposition
        let decomp_amount = vec![]; // Amount is public, so we do not need bit decomposition witnesses
        let decomp_sender =
            Self::decompose_compose_for_withdraw(sender_new.amount, net0, rep3_state)?;

        Ok((
            sender_new,
            receiver_new,
            inputs,
            traces,
            decomp_amount,
            decomp_sender,
        ))
    }

    #[expect(clippy::type_complexity)]
    pub fn process_dummy() -> eyre::Result<(
        DepositValueShare<F>,
        DepositValueShare<F>,
        Vec<Rep3AcvmType<F>>,
        Vec<Vec<Rep3AcvmType<F>>>,
        Vec<Rep3PrimeFieldShare<F>>,
        Vec<Rep3PrimeFieldShare<F>>,
    )> {
        let mut plain_traces =
            super::poseidon2_plain_commitment_helper::<1, _, _>([F::zero(), F::zero()]);
        plain_traces.push(plain_traces[0].clone());
        plain_traces.push(plain_traces[0].clone());
        plain_traces.push(plain_traces[0].clone());
        plain_traces.push(plain_traces[0].clone());

        let zero: crate::data_structure::DepositValue<Rep3PrimeFieldShare<_>> =
            DepositValueShare::new(
                Rep3PrimeFieldShare::zero_share(),
                Rep3PrimeFieldShare::zero_share(),
            );

        // Elements are public, so we do not need bit decomposition witnesses
        let decomp_amount = vec![];
        let decomp_sender = vec![];

        let inputs = vec![Rep3AcvmType::from(F::zero()); 8];

        Ok((
            zero.clone(),
            zero,
            inputs,
            plain_traces,
            decomp_amount,
            decomp_sender,
        ))
    }

    #[expect(clippy::type_complexity)]
    pub fn process_queue_with_r1cs_witness<N: Network>(
        &mut self,
        queue: Vec<Action<K>>,
        proof_schema: &NoirProofScheme<F>,
        nets: &[N; NUM_TRANSACTIONS * 2],
        rep3_states: &mut [Rep3State; NUM_TRANSACTIONS],
    ) -> eyre::Result<(
        Vec<DepositValueShare<F>>,
        Vec<DepositValueShare<F>>,
        Rep3SharedWitness<F>,
    )> {
        assert_eq!(queue.len(), NUM_TRANSACTIONS);
        let mut sender_new = Vec::with_capacity(NUM_TRANSACTIONS);
        let mut receiver_new = Vec::with_capacity(NUM_TRANSACTIONS);
        let mut proof_inputs = Vec::with_capacity(NUM_TRANSACTIONS * 8);
        let mut traces = Vec::with_capacity(NUM_COMMITMENTS);
        // The compiler groups bitdecomps by bits, so we have to store both used ones separately first
        let mut bitdecomps1 = Vec::with_capacity(NUM_TRANSACTIONS * 2);
        let mut bitdecomps2 = Vec::with_capacity(NUM_TRANSACTIONS);

        let my_id = PartyID::try_from(nets[0].id())?;

        let result = thread::scope(|scope| {
            let mut handles = Vec::with_capacity(3);
            for (action, nets, rep3_state) in
                izip!(queue, nets.chunks_exact(2), rep3_states.iter_mut())
            {
                match action {
                    Action::Transfer(sender, receiver, amount, amount_blinding) => {
                        let (sender_old, sender_new, receiver_old, receiver_new) =
                            self.transaction(sender, receiver, amount, rep3_state)?;
                        let handle = scope.spawn(move || {
                            Self::process_transaction(
                                sender_old,
                                receiver_old,
                                sender_new,
                                receiver_new,
                                amount,
                                amount_blinding,
                                &nets[0],
                                &nets[1],
                                rep3_state,
                            )
                        });
                        handles.push(handle);
                    }
                    Action::Deposit(receiver, amount) => {
                        let amount_shared =
                            rep3::arithmetic::promote_to_trivial_share(my_id, amount);
                        let (receiver_old, receiver_new) =
                            self.deposit(receiver, amount_shared, rep3_state);
                        let handle = scope.spawn(move || {
                            Self::process_deposit(
                                receiver_old,
                                receiver_new,
                                amount,
                                &nets[0],
                                rep3_state,
                            )
                        });
                        handles.push(handle);
                    }
                    Action::Withdraw(sender, amount) => {
                        let amount_shared =
                            rep3::arithmetic::promote_to_trivial_share(my_id, amount);
                        let (sender_old, sender_new) =
                            self.withdraw(sender, amount_shared, rep3_state)?;
                        let handle = scope.spawn(move || {
                            Self::process_withdraw(
                                sender_old, sender_new, amount, &nets[0], rep3_state,
                            )
                        });
                        handles.push(handle);
                    }
                    Action::Dummy => {
                        let handle = scope.spawn(move || Self::process_dummy());
                        handles.push(handle);
                    }
                    _ => eyre::bail!("Unsupported action in batched transaction processing"),
                }
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
    pub fn process_queue_with_groth16_proof<N: Network>(
        &mut self,
        queue: Vec<Action<K>>,
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
            self.process_queue_with_r1cs_witness(queue, proof_schema, nets, rep3_states)?;

        let (proof, public_inputs) = r1cs::prove(cs, pk, witness, &nets[0], &nets[1])
            .context("while generating Groth16 proof")?;

        Ok((sender_new, receiver_new, proof, public_inputs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{data_structure::DepositValue, proof::TestConfig};
    use ark_ff::UniformRand;
    use mpc_core::protocols::rep3::conversion::A2BType;
    use mpc_net::local::LocalNetwork;
    use rand::Rng;
    use std::sync::Arc;

    #[test]
    fn actionqueue_test() {
        // TestConfig::install_tracing();

        // Init Groth16
        // Read constraint system
        let pa = TestConfig::get_transaction_batched_program_artifact().unwrap();

        // Get the R1CS proof schema
        let mut rng = rand::thread_rng();
        let (proof_schema, pk, cs) = r1cs::setup_r1cs(pa, &mut rng).unwrap();
        let proof_schema: Arc<
            NoirProofScheme<ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4>>,
        > = Arc::new(proof_schema);
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
        let mut rng = rand::thread_rng();
        let mut plain_map =
            TestConfig::get_random_plain_map::<F, _>(TestConfig::NUM_ITEMS, &mut rng);
        let mut map_shares = plain_map.share(&mut rng);

        // The actual testcase
        // We test a batch with 3 transactions deposit to first new key, transfer between first and second new key, withdraw from second new key
        for _ in 0..TestConfig::TEST_RUNS {
            // Get two new random keys
            let key1 = TestConfig::get_random_new_key(&plain_map, &mut rng);
            let key2 = TestConfig::get_random_new_key(&plain_map, &mut rng);
            let amount = F::from(rng.r#gen::<u64>());
            let amount_blinding = F::rand(&mut rng);

            // Share the amount and the blinding
            let amount_share = rep3::share_field_element(amount, &mut rng);
            let amount_blinding_share = rep3::share_field_element(amount_blinding, &mut rng);

            // Action queue per party
            let mut action_queue_0 = Vec::with_capacity(NUM_TRANSACTIONS);
            let mut action_queue_1 = Vec::with_capacity(NUM_TRANSACTIONS);
            let mut action_queue_2 = Vec::with_capacity(NUM_TRANSACTIONS);

            // Deposit to key1
            action_queue_0.push(Action::Deposit(key1, amount));
            action_queue_1.push(Action::Deposit(key1, amount));
            action_queue_2.push(Action::Deposit(key1, amount));

            // Transfer from key1 to key2
            action_queue_0.push(Action::Transfer(
                key1,
                key2,
                amount_share[0],
                amount_blinding_share[0],
            ));
            action_queue_1.push(Action::Transfer(
                key1,
                key2,
                amount_share[1],
                amount_blinding_share[1],
            ));
            action_queue_2.push(Action::Transfer(
                key1,
                key2,
                amount_share[2],
                amount_blinding_share[2],
            ));

            // Withdraw from key2
            action_queue_0.push(Action::Withdraw(key2, amount));
            action_queue_1.push(Action::Withdraw(key2, amount));
            action_queue_2.push(Action::Withdraw(key2, amount));

            // Batch queues
            debug_assert_eq!(action_queue_0.len(), action_queue_1.len());
            debug_assert_eq!(action_queue_0.len(), action_queue_2.len());
            for _ in action_queue_0.len()..NUM_TRANSACTIONS {
                action_queue_0.push(Action::Dummy);
                action_queue_1.push(Action::Dummy);
                action_queue_2.push(Action::Dummy);
            }

            // Update plain map (just amount, ignore blinding)
            plain_map.insert(key1, DepositValue::new(F::zero(), F::zero()));
            plain_map.insert(key2, DepositValue::new(F::zero(), F::zero()));

            // Do the MPC work
            let (proof, public_inputs) = thread::scope(|scope| {
                let mut handles = Vec::with_capacity(3);
                for (nets, map, transaction) in izip!(
                    [
                        &mut test_networks0,
                        &mut test_networks1,
                        &mut test_networks2
                    ],
                    &mut map_shares,
                    [action_queue_0, action_queue_1, action_queue_2]
                ) {
                    let proof_schema = proof_schema.clone();
                    let cs = cs.clone();
                    let pk = pk.clone();
                    let handle = scope.spawn(move || {
                        let mut rep3_states = Vec::with_capacity(nets.len() / 2);
                        for net in nets.iter().take(nets.len() / 2) {
                            rep3_states.push(Rep3State::new(net, A2BType::default()).unwrap());
                        }

                        let (_sender_read, _receiver_read, proof, public_inputs) = map
                            .process_queue_with_groth16_proof(
                                transaction,
                                &proof_schema,
                                &cs,
                                &pk,
                                nets.as_slice().try_into().unwrap(),
                                rep3_states.as_mut_slice().try_into().unwrap(),
                            )
                            .unwrap();

                        (proof, public_inputs)
                    });
                    handles.push(handle);
                }

                let (proof0, public_inputs0) = handles.remove(0).join().unwrap();
                for handle in handles {
                    let (proof, public_inputs) = handle.join().unwrap();
                    assert_eq!(proof, proof0);
                    assert_eq!(public_inputs, public_inputs0);
                }
                (proof0, public_inputs0)
            });

            // Verifiy the results
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
