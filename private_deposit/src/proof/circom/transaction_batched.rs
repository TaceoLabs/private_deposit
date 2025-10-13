use crate::{
    data_structure::{DepositValueShare, PrivateDeposit},
    proof::{
        Curve, F,
        transaction_batched::{NUM_TRANSACTIONS, TransactionInput},
    },
};
use ark_ff::Zero;
use ark_groth16::Proof;
use circom_mpc_vm::{Rep3VmType, mpc_vm::Rep3WitnessExtension};
use co_circom::{CoCircomCompilerParsed, Rep3SharedWitness, VMConfig};
use co_noir_to_r1cs::{circom::proof_schema::CircomProofSchema, noir::r1cs};
use eyre::Context;
use mpc_core::protocols::rep3::{Rep3PrimeFieldShare, Rep3State};
use mpc_net::Network;
use std::collections::BTreeMap;

impl<K> PrivateDeposit<K, DepositValueShare<F>>
where
    K: std::hash::Hash + Eq + Clone,
{
    #[expect(clippy::too_many_arguments)]
    fn add_to_circom_tranasction_input(
        i: usize,
        inputs: &mut BTreeMap<String, Rep3VmType<F>>,
        sender_old: DepositValueShare<F>,
        receiver_old: Option<DepositValueShare<F>>,
        amount: Rep3PrimeFieldShare<F>,
        amount_blinding: Rep3PrimeFieldShare<F>,
        sender_new_blinding: Rep3PrimeFieldShare<F>,
        receiver_new_blinding: Rep3PrimeFieldShare<F>,
    ) {
        inputs.insert(
            format!("sender_old_balance[{i}]").to_string(),
            Rep3VmType::from(sender_old.amount),
        );
        inputs.insert(
            format!("sender_old_r[{i}]").to_string(),
            Rep3VmType::from(sender_old.blinding),
        );
        if let Some(old) = receiver_old {
            inputs.insert(
                format!("receiver_old_balance[{i}]").to_string(),
                Rep3VmType::from(old.amount),
            );
            inputs.insert(
                format!("receiver_old_r[{i}]").to_string(),
                Rep3VmType::from(old.blinding),
            );
        } else {
            inputs.insert(
                format!("receiver_old_balance[{i}]").to_string(),
                Rep3VmType::from(F::zero()),
            );
            inputs.insert(
                format!("receiver_old_r[{i}]").to_string(),
                Rep3VmType::from(F::zero()),
            );
        };
        inputs.insert(format!("amount[{i}]").to_string(), Rep3VmType::from(amount));
        inputs.insert(
            format!("amount_r[{i}]").to_string(),
            Rep3VmType::from(amount_blinding),
        );
        inputs.insert(
            format!("sender_new_r[{i}]").to_string(),
            Rep3VmType::from(sender_new_blinding),
        );
        inputs.insert(
            format!("receiver_new_r[{i}]").to_string(),
            Rep3VmType::from(receiver_new_blinding),
        );
    }

    #[expect(clippy::type_complexity)]
    pub fn transaction_batched_with_cocircom_witext<N: Network>(
        &mut self,
        inputs: &[TransactionInput<K, Rep3PrimeFieldShare<F>>; NUM_TRANSACTIONS],
        circuit: &CoCircomCompilerParsed<F>,
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
        let mut proof_inputs = BTreeMap::new();

        for (i, input) in inputs.iter().enumerate() {
            let (sender_old, sender_new_, receiver_old, receiver_new_) = self.transaction(
                input.sender_key.clone(),
                input.receiver_key.clone(),
                input.amount,
                rep3_state,
            )?;

            Self::add_to_circom_tranasction_input(
                i,
                &mut proof_inputs,
                sender_old,
                receiver_old,
                input.amount,
                input.amount_blinding,
                sender_new_.blinding,
                receiver_new_.blinding,
            );

            sender_new.push(sender_new_);
            receiver_new.push(receiver_new_);
        }

        // init MPC protocol
        let rep3_vm = Rep3WitnessExtension::new(net0, net1, circuit, VMConfig::default())
            .context("while constructing MPC VM")?;

        // execute witness generation in MPC
        let witness = rep3_vm
            .run(proof_inputs, circuit.public_inputs().len())
            .context("while running witness generation")?
            .into_shared_witness();

        Ok((sender_new, receiver_new, witness))
    }

    #[expect(clippy::type_complexity)]
    pub fn transaction_batched_with_cocircom_proof<N: Network>(
        &mut self,
        inputs: &[TransactionInput<K, Rep3PrimeFieldShare<F>>; NUM_TRANSACTIONS],
        circuit: &CoCircomCompilerParsed<F>,
        proof_schema: &CircomProofSchema<Curve>,
        net0: &N,
        net1: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(
        Vec<DepositValueShare<F>>,
        Vec<DepositValueShare<F>>,
        Proof<Curve>,
        Vec<F>,
    )> {
        let (sender_new, receiver_new, witness) =
            self.transaction_batched_with_cocircom_witext(inputs, circuit, net0, net1, rep3_state)?;

        let (proof, public_inputs) = r1cs::prove(
            &proof_schema.matrices,
            &proof_schema.pk,
            witness,
            net0,
            net1,
        )
        .context("while generating Groth16 proof")?;

        Ok((sender_new, receiver_new, proof, public_inputs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{data_structure::DepositValuePlain, proof::TestConfig};
    use ark_ff::{PrimeField, UniformRand};
    use itertools::izip;
    use mpc_core::protocols::rep3::{self, conversion::A2BType};
    use mpc_net::local::LocalNetwork;
    use rand::Rng;
    use std::{array, sync::Arc, thread};

    #[test]
    #[ignore = "This test is slow in debug mode"]
    fn transaction_batched_cocircom_test() {
        // TestConfig::install_tracing();

        // Init Groth16
        // Read circom file
        let pa = TestConfig::get_transaction_batched_circom().unwrap();
        let pa = Arc::new(pa);

        // Get the R1CS proof schema
        let mut rng = rand::thread_rng();
        let proof_schema = TestConfig::get_transaction_batched_proof_schema(&mut rng).unwrap();
        let proof_schema = Arc::new(proof_schema);
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
                    let pa = pa.clone();
                    let proof_schema = proof_schema.clone();
                    let handle = scope.spawn(move || {
                        let mut rep3 = Rep3State::new(net0, A2BType::default()).unwrap();

                        let (sender_read, receiver_read, proof, public_inputs) = map
                            .transaction_batched_with_cocircom_proof(
                                transaction.as_slice().try_into().unwrap(),
                                &pa,
                                &proof_schema,
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
