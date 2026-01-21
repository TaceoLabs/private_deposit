use crate::data_structure::{DepositValueShare, PrivateDeposit};
use crate::proof::actionquery::Action;
use crate::proof::circom::POSEIDON2_SPONGE_T;
use crate::proof::transaction::NUM_TRANSACTION_COMMITMENTS;
use crate::proof::transaction_batched::{NUM_COMMITMENTS, NUM_TRANSACTIONS};
use crate::proof::{
    Curve, F, NUM_AMOUNT_BITS, NUM_WITHDRAW_NEW_BITS, decompose_compose_for_transaction,
    decompose_compose_public,
};
use ark_ff::Zero;
use ark_groth16::Proof;
use circom_mpc_vm::mpc_vm::Rep3WitnessExtension;
use circom_mpc_vm::{ComponentAcceleratorOutput, Rep3VmType};
use co_circom::{CoCircomCompilerParsed, Rep3SharedWitness, VMConfig};
use co_noir_to_r1cs::circom::proof_schema::CircomProofSchema;
use co_noir_to_r1cs::noir::r1cs;
use eyre::Context;
use itertools::{Itertools, izip};
use mpc_core::protocols::rep3::id::PartyID;
use mpc_core::protocols::rep3::{self, Rep3PrimeFieldShare, Rep3State, arithmetic};
use mpc_net::Network;
use std::collections::BTreeMap;
use std::thread;
use std::time::{Duration, Instant};

impl<K> PrivateDeposit<K, DepositValueShare<F>>
where
    K: std::hash::Hash + Eq + Clone + Send + Sync,
{
    #[expect(clippy::type_complexity, clippy::too_many_arguments)]
    pub fn process_transaction_circom_compressed<N: Network>(
        sender_old: DepositValueShare<F>,
        receiver_old: Option<DepositValueShare<F>>,
        sender_new: DepositValueShare<F>,
        receiver_new: DepositValueShare<F>,
        amount: Rep3PrimeFieldShare<F>,
        amount_blinding: Rep3PrimeFieldShare<F>,
        net0: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(
        DepositValueShare<F>,
        DepositValueShare<F>,
        Vec<Rep3VmType<F>>,
        Vec<ComponentAcceleratorOutput<Rep3VmType<F>>>,
        [F; NUM_TRANSACTION_COMMITMENTS],
    )> {
        let (inputs, receiver_old_amount, receiver_old_blinding) =
            Self::get_query_transaction_circom_input(
                sender_old.to_owned(),
                receiver_old,
                amount,
                amount_blinding,
                sender_new.blinding,
                receiver_new.blinding,
            );
        let input_commitment = [
            amount,
            amount_blinding,
            sender_old.amount,
            sender_old.blinding,
            sender_new.amount,
            sender_new.blinding,
            receiver_old_amount,
            receiver_old_blinding,
            receiver_new.amount,
            receiver_new.blinding,
        ];
        let mut state = input_commitment;

        let mut traces =
            super::poseidon2_circom_commitment_helper::<NUM_TRANSACTION_COMMITMENTS, _, _, _>(
                &mut state, net0, rep3_state,
            )?;

        let ff_commitments = super::feed_forward_shared::<
            2,
            NUM_TRANSACTION_COMMITMENTS,
            { 2 * NUM_TRANSACTION_COMMITMENTS },
            _,
        >(state, input_commitment);

        let mut opened_commitments: [F; NUM_TRANSACTION_COMMITMENTS] =
            arithmetic::open_vec(&ff_commitments, net0)?
                .try_into()
                .expect("should fit");
        opened_commitments.rotate_left(1); // Amount commitment is at the end for the sponge input 

        // The bit decompositions
        let (decomp_amount, decomp_sender) =
            decompose_compose_for_transaction(amount, sender_new.amount, net0, rep3_state)?;
        traces.insert(
            1,
            ComponentAcceleratorOutput::new(
                decomp_sender
                    .iter()
                    .map(|x| Rep3VmType::from(*x))
                    .collect_vec(),
                Vec::new(),
            ),
        );
        traces.insert(
            0,
            ComponentAcceleratorOutput::new(
                decomp_amount
                    .iter()
                    .map(|x| Rep3VmType::from(*x))
                    .collect_vec(),
                Vec::new(),
            ),
        );

        Ok((sender_new, receiver_new, inputs, traces, opened_commitments))
    }

    #[expect(clippy::type_complexity)]
    pub fn process_deposit_circom_compressed<N: Network>(
        receiver_old: Option<DepositValueShare<F>>,
        receiver_new: DepositValueShare<F>,
        amount: F,
        net0: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(
        DepositValueShare<F>,
        DepositValueShare<F>,
        Vec<Rep3VmType<F>>,
        Vec<ComponentAcceleratorOutput<Rep3VmType<F>>>,
        [F; NUM_TRANSACTION_COMMITMENTS],
    )> {
        let (inputs, receiver_old_amount, receiver_old_blinding) =
            Self::get_deposit_input_public_amount_circom(
                receiver_old,
                amount,
                F::zero(),
                receiver_new.blinding,
            );

        let sender_new = DepositValueShare::<F>::new(
            Rep3PrimeFieldShare::zero_share(),
            Rep3PrimeFieldShare::zero_share(),
        );
        let input_commitment = [
            receiver_old_amount,
            receiver_old_blinding,
            receiver_new.amount,
            receiver_new.blinding,
        ];
        let mut state = input_commitment;

        let mut traces =
            super::poseidon2_circom_commitment_helper::<2, _, _, _>(&mut state, net0, rep3_state)?;

        let plain_traces = super::poseidon2_plain_circom_commitment_helper::<2, 2, _, _>([
            amount,
            F::zero(),
            F::zero(),
            F::zero(),
        ])?;

        let states_public = plain_traces.iter().flat_map(|trace| trace.0).collect_vec();
        let mut decomp_amount = decompose_compose_public::<NUM_AMOUNT_BITS>(&[amount]);

        let first_output = ComponentAcceleratorOutput::new(
            plain_traces[0].0.iter().map(|x| (*x).into()).collect(),
            plain_traces[0].1.iter().map(|x| (*x).into()).collect(),
        );

        traces.insert(0, first_output.clone());
        traces.insert(0, first_output);
        traces.insert(
            2,
            ComponentAcceleratorOutput::new(
                plain_traces[1].0.iter().map(|x| (*x).into()).collect(),
                plain_traces[1].1.iter().map(|x| (*x).into()).collect(),
            ),
        );
        traces.insert(
            1,
            ComponentAcceleratorOutput::new(
                vec![Rep3VmType::default(); NUM_WITHDRAW_NEW_BITS],
                Vec::new(),
            ),
        );
        traces.insert(
            0,
            ComponentAcceleratorOutput::new(
                decomp_amount
                    .remove(0)
                    .iter()
                    .map(|x| Rep3VmType::from(*x))
                    .collect_vec(),
                Vec::new(),
            ),
        );

        let ff_commmitments_shared =
            super::feed_forward_shared::<2, 2, 4, _>(state, input_commitment);

        let ff_commitments_public = super::feed_forward_public::<2, 1, 2, _>(
            states_public[..2].try_into().expect("should fit"),
            [amount, F::zero()],
        );

        let opened_commitments = arithmetic::open_vec(&ff_commmitments_shared, net0)?;

        let opened_commitments_final = [
            ff_commitments_public[0],
            states_public[2],
            opened_commitments[0],
            opened_commitments[1],
            ff_commitments_public[0],
        ];

        Ok((
            sender_new,
            receiver_new,
            inputs,
            traces,
            opened_commitments_final,
        ))
    }

    #[expect(clippy::type_complexity)]
    pub fn process_withdraw_circom_compressed<N: Network>(
        sender_old: DepositValueShare<F>,
        sender_new: DepositValueShare<F>,
        amount: F,
        net0: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(
        DepositValueShare<F>,
        DepositValueShare<F>,
        Vec<Rep3VmType<F>>,
        Vec<ComponentAcceleratorOutput<Rep3VmType<F>>>,
        [F; NUM_TRANSACTION_COMMITMENTS],
    )> {
        let my_id = PartyID::try_from(net0.id())?;
        let inputs = Self::get_query_withdraw_circom_input_public_amount(
            sender_old.to_owned(),
            amount,
            F::zero(),
            sender_new.blinding,
        );

        let receiver_new = DepositValueShare::new(
            rep3::arithmetic::promote_to_trivial_share(my_id, amount),
            Rep3PrimeFieldShare::zero_share(),
        );

        let input_commitment = [
            sender_old.amount,
            sender_old.blinding,
            sender_new.amount,
            sender_new.blinding,
        ];
        let mut state = input_commitment;

        let mut traces =
            super::poseidon2_circom_commitment_helper::<2, _, _, _>(&mut state, net0, rep3_state)?;

        let plain_traces = super::poseidon2_plain_circom_commitment_helper::<2, 2, _, _>([
            amount,
            F::zero(),
            F::zero(),
            F::zero(),
        ])?;
        let states_public = plain_traces.iter().flat_map(|trace| trace.0).collect_vec();

        let decomp_sender =
            Self::decompose_compose_for_withdraw(sender_new.amount, net0, rep3_state)?;
        let mut decomp_amount = decompose_compose_public::<NUM_AMOUNT_BITS>(&[amount]);

        let first_output = ComponentAcceleratorOutput::new(
            plain_traces[0].0.iter().map(|x| (*x).into()).collect(),
            plain_traces[0].1.iter().map(|x| (*x).into()).collect(),
        );
        traces.insert(0, first_output.clone());
        traces.push(ComponentAcceleratorOutput::new(
            plain_traces[1].0.iter().map(|x| (*x).into()).collect(),
            plain_traces[1].1.iter().map(|x| (*x).into()).collect(),
        ));
        traces.push(first_output);

        traces.insert(
            1,
            ComponentAcceleratorOutput::new(
                decomp_sender
                    .into_iter()
                    .map(Rep3VmType::from)
                    .collect_vec(),
                Vec::new(),
            ),
        );
        traces.insert(
            0,
            ComponentAcceleratorOutput::new(
                decomp_amount
                    .remove(0)
                    .into_iter()
                    .map(Rep3VmType::from)
                    .collect_vec(),
                Vec::new(),
            ),
        );

        let ff_commmitments_shared =
            super::feed_forward_shared::<2, 2, 4, _>(state, input_commitment);

        let ff_commitments_public = super::feed_forward_public::<2, 1, 2, _>(
            states_public[..2].try_into().expect("should fit"),
            [amount, F::zero()],
        );

        let opened_commitments = arithmetic::open_vec(&ff_commmitments_shared, net0)?;

        let opened_commitments_final = [
            opened_commitments[0],
            opened_commitments[1],
            states_public[2],
            ff_commitments_public[0],
            ff_commitments_public[0],
        ];

        Ok((
            sender_new,
            receiver_new,
            inputs,
            traces,
            opened_commitments_final,
        ))
    }

    #[expect(clippy::type_complexity)]
    pub fn process_dummy_circom_compressed() -> eyre::Result<(
        DepositValueShare<F>,
        DepositValueShare<F>,
        Vec<Rep3VmType<F>>,
        Vec<ComponentAcceleratorOutput<Rep3VmType<F>>>,
        [F; NUM_TRANSACTION_COMMITMENTS],
    )> {
        let mut plain_traces =
            super::poseidon2_plain_circom_commitment_helper::<2, 1, _, _>([F::zero(), F::zero()])?;

        let first_state_public = plain_traces[0].0[0];

        plain_traces.push(plain_traces[0].clone());
        plain_traces.push(plain_traces[0].clone());
        plain_traces.push(plain_traces[0].clone());
        plain_traces.push(plain_traces[0].clone());

        let zero: crate::data_structure::DepositValue<Rep3PrimeFieldShare<_>> =
            DepositValueShare::new(
                Rep3PrimeFieldShare::zero_share(),
                Rep3PrimeFieldShare::zero_share(),
            );

        let mut plain_traces: Vec<ComponentAcceleratorOutput<Rep3VmType<F>>> = plain_traces
            .into_iter()
            .map(|trace| {
                ComponentAcceleratorOutput::new(
                    trace.0.into_iter().map(|x| x.into()).collect(),
                    trace.1.into_iter().map(|x| x.into()).collect(),
                )
            })
            .collect();
        plain_traces.insert(
            1,
            ComponentAcceleratorOutput::new(
                vec![Rep3VmType::default(); NUM_WITHDRAW_NEW_BITS],
                Vec::new(),
            ),
        );
        plain_traces.insert(
            0,
            ComponentAcceleratorOutput::new(
                vec![Rep3VmType::default(); NUM_AMOUNT_BITS],
                Vec::new(),
            ),
        );
        let inputs = vec![Rep3VmType::default(); 8];

        // If not zero, this would need to into the output accordingly
        // let ff_commitments_public = super::feed_forward_public::<2, 1, 2, _>(
        //     states_public.try_into().expect("should fit"),
        //     [F::zero(); 2],
        // );

        Ok((
            zero.clone(),
            zero,
            inputs,
            plain_traces,
            [first_state_public; NUM_TRANSACTION_COMMITMENTS],
        ))
    }

    #[expect(clippy::type_complexity)]
    pub fn process_queue_with_cocircom_witext_compressed<N: Network>(
        &mut self,
        queue: Vec<Action<K>>,
        circuit: &CoCircomCompilerParsed<F>,
        nets: &[N; NUM_TRANSACTIONS * 2],
        rep3_states: &mut [Rep3State; NUM_TRANSACTIONS],
    ) -> eyre::Result<(
        Vec<DepositValueShare<F>>,
        Vec<DepositValueShare<F>>,
        Rep3SharedWitness<F>,
        Vec<F>,
    )> {
        assert_eq!(queue.len(), NUM_TRANSACTIONS);
        let mut sender_new = Vec::with_capacity(NUM_TRANSACTIONS);
        let mut receiver_new = Vec::with_capacity(NUM_TRANSACTIONS);
        let mut proof_inputs = BTreeMap::new();
        let mut traces = Vec::with_capacity(NUM_COMMITMENTS);
        let mut opened_commitments = Vec::with_capacity(NUM_COMMITMENTS);
        let mut new_balance_commitments = Vec::with_capacity(NUM_TRANSACTIONS * 2);

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
                            Self::process_transaction_circom_compressed(
                                sender_old,
                                receiver_old,
                                sender_new,
                                receiver_new,
                                amount,
                                amount_blinding,
                                &nets[0],
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
                            Self::process_deposit_circom_compressed(
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
                            Self::process_withdraw_circom_compressed(
                                sender_old, sender_new, amount, &nets[0], rep3_state,
                            )
                        });
                        handles.push(handle);
                    }
                    Action::Dummy => {
                        let handle = scope.spawn(move || Self::process_dummy_circom_compressed());
                        handles.push(handle);
                    }
                    _ => eyre::bail!("Unsupported action in batched transaction processing"),
                }
            }

            for (i, handle) in handles.into_iter().enumerate() {
                let (sender_new_, receiver_new_, inputs_, traces_, commitments_opened) =
                    handle.join().map_err(|_| {
                        eyre::eyre!("A thread panicked while processing a transaction")
                    })??;
                sender_new.push(sender_new_);
                receiver_new.push(receiver_new_);
                opened_commitments.extend(commitments_opened);
                Self::add_inputs_to_circom_map(i, inputs_, &mut proof_inputs);
                traces.extend(traces_);
            }
            assert_eq!(opened_commitments.len(), NUM_COMMITMENTS);
            new_balance_commitments.push(opened_commitments[9]);
            new_balance_commitments.push(opened_commitments[3]);
            new_balance_commitments.push(opened_commitments[6]);
            new_balance_commitments.push(opened_commitments[8]);
            new_balance_commitments.push(opened_commitments[11]);
            let (final_traces, alpha) =
                super::compression_commitment_helper::<POSEIDON2_SPONGE_T, NUM_COMMITMENTS, _>(
                    opened_commitments
                        .try_into()
                        .expect("we checked lengths before"),
                )?;
            proof_inputs.insert("alpha".to_string(), alpha.into());
            traces.extend(final_traces);
            Result::<_, eyre::Report>::Ok(())
        });
        result?;

        // init MPC protocol
        let rep3_vm = Rep3WitnessExtension::new(&nets[0], &nets[1], circuit, VMConfig::default())
            .context("while constructing MPC VM")?;

        // execute witness generation in MPC
        let witness = rep3_vm
            .run_with_helper_trace(
                proof_inputs,
                circuit.public_inputs().len(),
                &mut Some(traces),
            )
            .context("while running witness generation")?
            .into_shared_witness();

        Ok((sender_new, receiver_new, witness, new_balance_commitments))
    }

    #[expect(clippy::type_complexity)]
    pub fn process_queue_with_cocircom_proof_compressed<N: Network>(
        &mut self,
        queue: Vec<Action<K>>,
        circuit: &CoCircomCompilerParsed<F>,
        proof_schema: &CircomProofSchema<Curve>,
        nets: &[N; NUM_TRANSACTIONS * 2],
        rep3_states: &mut [Rep3State; NUM_TRANSACTIONS],
    ) -> eyre::Result<(
        Vec<DepositValueShare<F>>,
        Vec<DepositValueShare<F>>,
        Proof<Curve>,
        Vec<F>,
        Vec<F>,
        Duration,
    )> {
        let (sender_new, receiver_new, witness, new_balance_commitments) =
            self.process_queue_with_cocircom_witext_compressed(queue, circuit, nets, rep3_states)?;

        // generate proof
        let start = Instant::now();
        let (proof, public_inputs) = r1cs::prove(
            &proof_schema.matrices,
            &proof_schema.pk,
            witness,
            &nets[0],
            &nets[1],
        )
        .context("while generating Groth16 proof")?;
        let duration = start.elapsed();

        Ok((
            sender_new,
            receiver_new,
            proof,
            public_inputs,
            new_balance_commitments,
            duration,
        ))
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
    fn actionqueue_circom_compressed_test() {
        // TestConfig::install_tracing();

        // Init Groth16
        // Read constraint system
        let pa = TestConfig::get_transaction_batched_circom_compressed().unwrap();
        let pa = Arc::new(pa);

        // Get the R1CS proof schema
        let mut rng = rand::thread_rng();
        let proof_schema =
            TestConfig::get_transaction_batched_proof_schema_compressed(&mut rng).unwrap();
        let proof_schema = Arc::new(proof_schema);
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

            // // Batch queues
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
                    let pa = pa.clone();
                    let proof_schema = proof_schema.clone();
                    let handle = scope.spawn(move || {
                        let mut rep3_states = Vec::with_capacity(nets.len() / 2);
                        for net in nets.iter().take(nets.len() / 2) {
                            rep3_states.push(Rep3State::new(net, A2BType::default()).unwrap());
                        }

                        let (
                            _sender_read,
                            _receiver_read,
                            proof,
                            public_inputs,
                            _,
                            _proof_duration,
                        ) = map
                            .process_queue_with_cocircom_proof_compressed(
                                transaction,
                                &pa,
                                &proof_schema,
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
            assert!(r1cs::verify(&proof_schema.pk.vk, &proof, &public_inputs).unwrap());
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
