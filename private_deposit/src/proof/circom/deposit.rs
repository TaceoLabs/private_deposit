use crate::{
    data_structure::{DepositValueShare, PrivateDeposit},
    proof::{Curve, F},
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
    K: std::hash::Hash + Eq,
{
    fn get_deposit_circom_input(
        old: Option<DepositValueShare<F>>,
        amount: Rep3PrimeFieldShare<F>,
        amount_blinding: Rep3PrimeFieldShare<F>,
        new_blinding: Rep3PrimeFieldShare<F>,
    ) -> BTreeMap<String, Rep3VmType<F>> {
        let mut inputs = BTreeMap::new();
        if let Some(old) = old {
            inputs.insert("old_balance".to_string(), Rep3VmType::from(old.amount));
            inputs.insert("old_r".to_string(), Rep3VmType::from(old.blinding));
        } else {
            inputs.insert("old_balance".to_string(), Rep3VmType::from(F::zero()));
            inputs.insert("old_r".to_string(), Rep3VmType::from(F::zero()));
        };
        inputs.insert("amount".to_string(), Rep3VmType::from(amount));
        inputs.insert("amount_r".to_string(), Rep3VmType::from(amount_blinding));
        inputs.insert("new_r".to_string(), Rep3VmType::from(new_blinding));
        inputs
    }

    #[expect(clippy::too_many_arguments)]
    pub fn deposit_with_cocircom_witext<N: Network>(
        &mut self,
        key: K,
        amount: Rep3PrimeFieldShare<F>,
        amount_blinding: Rep3PrimeFieldShare<F>, // For the commitment to the amount
        circuit: &CoCircomCompilerParsed<F>,
        net0: &N,
        net1: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(DepositValueShare<F>, Rep3SharedWitness<F>)> {
        let (old, new) = self.deposit(key, amount, rep3_state);

        let inputs = Self::get_deposit_circom_input(old, amount, amount_blinding, new.blinding);

        // init MPC protocol
        let rep3_vm = Rep3WitnessExtension::new(net0, net1, circuit, VMConfig::default())
            .context("while constructing MPC VM")?;

        // execute witness generation in MPC
        let witness = rep3_vm
            .run(inputs, circuit.public_inputs().len())
            .context("while running witness generation")?
            .into_shared_witness();

        Ok((new, witness))
    }

    #[expect(clippy::too_many_arguments)]
    pub fn deposit_with_cocircom_proof<N: Network>(
        &mut self,
        key: K,
        amount: Rep3PrimeFieldShare<F>,
        amount_blinding: Rep3PrimeFieldShare<F>, // For the commitment to the amount
        circuit: &CoCircomCompilerParsed<F>,
        proof_schema: &CircomProofSchema<Curve>,
        net0: &N,
        net1: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(DepositValueShare<F>, Proof<Curve>, Vec<F>)> {
        let (new, witness) = self.deposit_with_cocircom_witext(
            key,
            amount,
            amount_blinding,
            circuit,
            net0,
            net1,
            rep3_state,
        )?;

        let (proof, public_inputs) = r1cs::prove(
            &proof_schema.matrices,
            &proof_schema.pk,
            witness,
            net0,
            net1,
        )
        .context("while generating Groth16 proof")?;

        Ok((new, proof, public_inputs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{data_structure::DepositValuePlain, proof::TestConfig};
    use ark_ff::UniformRand;
    use itertools::izip;
    use mpc_core::protocols::rep3::{self, conversion::A2BType};
    use mpc_net::local::LocalNetwork;
    use rand::Rng;
    use std::{sync::Arc, thread};

    #[test]
    fn deposit_cocircom_test() {
        // TestConfig::install_tracing();

        // Init Groth16
        // Read circom file
        let pa = TestConfig::get_deposit_circom().unwrap();
        let pa = Arc::new(pa);

        // Get the R1CS proof schema
        let mut rng = rand::thread_rng();
        let proof_schema = TestConfig::get_deposit_proof_schema(&mut rng).unwrap();
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
        let mut plain_map =
            TestConfig::get_random_plain_map::<F, _>(TestConfig::NUM_ITEMS, &mut rng);
        let mut map_shares = plain_map.share(&mut rng);

        // The actual testcase
        for _ in 0..TestConfig::TEST_RUNS {
            // Either new key or existing key, with 50% probability each
            let key = if rng.r#gen::<bool>() {
                F::rand(&mut rng)
            } else {
                TestConfig::get_random_map_key(&plain_map, &mut rng)
            };
            let amount = F::from(rng.r#gen::<u64>());
            let amount_blinding = F::rand(&mut rng);

            // Insert (just the amount) into the plain map
            let read_plain = plain_map.get(&key);
            let result_amount = if let Some(v) = read_plain {
                amount + v.amount
            } else {
                amount
            };
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
                    let pa = pa.clone();
                    let proof_schema = proof_schema.clone();
                    let handle = scope.spawn(move || {
                        let mut rep3 = Rep3State::new(net0, A2BType::default()).unwrap();

                        let (read, proof, public_inputs) = map
                            .deposit_with_cocircom_proof(
                                key,
                                amount,
                                amount_blinding,
                                &pa,
                                &proof_schema,
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
