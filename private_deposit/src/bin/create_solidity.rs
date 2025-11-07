use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{UniformRand, Zero};
use co_circom::{ConstraintMatrices, ProvingKey};
use co_noir::Bn254;
use co_noir_to_r1cs::{
    circom::solidity_verifier, noir::r1cs, r1cs::noir_proof_schema::NoirProofScheme,
};
use itertools::izip;
use mpc_core::{
    gadgets::poseidon2::Poseidon2,
    protocols::rep3::{self, Rep3State, conversion::A2BType},
};
use mpc_net::local::LocalNetwork;
use private_deposit::{
    data_structure::{DepositValue, PrivateDeposit},
    proof::{NUM_BATCHED_TRANSACTIONS, TestConfig, actionquery::Action},
};
use rand::{CryptoRng, Rng};
use rand_chacha::{ChaCha12Rng, rand_core::SeedableRng};
use std::{fs::File, io::Write, process::ExitCode, thread};

const ROOT: &str = std::env!("CARGO_MANIFEST_DIR");
const PATH: &str = "/../contracts/src/groth16_verifier.sol";
const SEED: &str = "SOLIDITY_DEPOSIT";

type F = ark_bn254::Fr;
type Curve = Bn254;

// This file creates the solidity verifier for the transaction circuit from a seed. Keep in mind that the ZKEY is created from the seed and not in a ceremony, thus insecure! This is only for testing purposes!

fn create_action_queues<R: Rng + CryptoRng>(
    key1: F,
    key2: F,
    amount: F,
    amount_blinding: F,
    mpc_keys: [ark_babyjubjub::EdwardsAffine; 3],
    rng: &mut R,
) -> [Vec<Action<F>>; 3] {
    let amount_share = rep3::share_field_element(amount, rng);
    let amount_blinding_share = rep3::share_field_element(amount_blinding, rng);

    let sender_key = ark_babyjubjub::Fr::rand(rng);
    let sender_pk = (ark_babyjubjub::EdwardsAffine::generator() * sender_key).into_affine();

    println!("// Sender Public Key");
    println!(
        "PrivateBalance.BabyJubJubElement sender_key = PrivateBalance.BabyJubJubElement(
            {},
            {}
        );",
        sender_pk.x, sender_pk.y
    );
    println!();
    println!("// Ciphertext components");
    for i in 0..3 {
        let shared_key = dh_key_derivation(&sender_key, mpc_keys[i]);
        let ciphertext = sym_encrypt(
            shared_key,
            [amount_share[i].a, amount_blinding_share[i].a],
            F::zero(),
        );
        println!("uint256 amount{} = {};", i, ciphertext[0]);
        println!("uint256 r{} = {};", i, ciphertext[1]);
    }
    println!();

    // Create the action queue
    let mut action_queue_0: Vec<
        Action<ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4>>,
    > = Vec::with_capacity(NUM_BATCHED_TRANSACTIONS);
    let mut action_queue_1 = Vec::with_capacity(NUM_BATCHED_TRANSACTIONS);
    let mut action_queue_2 = Vec::with_capacity(NUM_BATCHED_TRANSACTIONS);

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
    for _ in action_queue_0.len()..NUM_BATCHED_TRANSACTIONS {
        action_queue_0.push(Action::Dummy);
        action_queue_1.push(Action::Dummy);
        action_queue_2.push(Action::Dummy);
    }

    [action_queue_0, action_queue_1, action_queue_2]
}

// This function creates inputs to the solidity verifier test
#[expect(clippy::identity_op)]
fn test_process_mpc<R: Rng + CryptoRng>(
    proof_schema: &NoirProofScheme<F>,
    cs: &ConstraintMatrices<F>,
    pk: &ProvingKey<Curve>,
    mpc_keys: [ark_babyjubjub::EdwardsAffine; 3],
    rng: &mut R,
) -> eyre::Result<ExitCode> {
    let alice = F::from(1u64);
    let bob = F::from(2u64);
    let amount = F::from(1000000000000000000u64); // 1 ETH
    let amount_blinding = F::rand(rng);

    // prepare the map
    let plain_map: PrivateDeposit<F, DepositValue<F>> = PrivateDeposit::new();

    // Init networks
    let mut test_networks0 = Vec::with_capacity(NUM_BATCHED_TRANSACTIONS * 2);
    let mut test_networks1 = Vec::with_capacity(NUM_BATCHED_TRANSACTIONS * 2);
    let mut test_networks2 = Vec::with_capacity(NUM_BATCHED_TRANSACTIONS);
    for _ in 0..(NUM_BATCHED_TRANSACTIONS * 2) {
        let [net0, net1, net2] = LocalNetwork::new(3).try_into().unwrap();
        test_networks0.push(net0);
        test_networks1.push(net1);
        test_networks2.push(net2);
    }

    // Create shares
    let mut map_shares = plain_map.share(rng);

    // Get action queues
    let action_queues = create_action_queues(alice, bob, amount, amount_blinding, mpc_keys, rng);

    // Do the MPC work
    let result = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(3);
        for (nets, map, transaction) in izip!(
            [
                &mut test_networks0,
                &mut test_networks1,
                &mut test_networks2
            ],
            &mut map_shares,
            action_queues
        ) {
            let handle = scope.spawn(move || {
                let mut rep3_states = Vec::with_capacity(nets.len() / 2);
                for net in nets.iter().take(nets.len() / 2) {
                    rep3_states.push(Rep3State::new(net, A2BType::default())?);
                }

                let (_sender_read, _receiver_read, proof, public_inputs, _proof_time) = map
                    .process_queue_with_groth16_proof(
                        transaction,
                        proof_schema,
                        cs,
                        pk,
                        nets.as_slice().try_into().unwrap(),
                        rep3_states.as_mut_slice().try_into().unwrap(),
                    )?;

                Result::<_, eyre::Report>::Ok((proof, public_inputs))
            });
            handles.push(handle);
        }

        let (proof0, public_inputs0) = handles
            .remove(0)
            .join()
            .map_err(|_| eyre::eyre!("A thread panicked while processing a transaction"))??;
        for handle in handles {
            let (proof, public_inputs) = handle
                .join()
                .map_err(|_| eyre::eyre!("A thread panicked while processing a transaction"))??;
            assert_eq!(proof, proof0);
            assert_eq!(public_inputs, public_inputs0);
        }
        Result::<_, eyre::Report>::Ok((proof0, public_inputs0))
    });
    let (proof, public_inputs) = result?;

    // Verifiy the results
    if !r1cs::verify(&pk.vk, &proof, &public_inputs)? {
        return Err(eyre::eyre!("Proof verification failed"));
    }

    // Extract the proof
    let (ax, ay) = proof.a.xy().unwrap_or_default();
    let (bx, by) = proof.b.xy().unwrap_or_default();
    let (cx, cy) = proof.c.xy().unwrap_or_default();

    const NUM_COMMITMENTS_PER_TRANSACTION: usize = 5;
    println!("// The commitments");
    println!(
        "uint256 amount_commitment = {};",
        public_inputs[1 * NUM_COMMITMENTS_PER_TRANSACTION + 4]
    );
    println!("uint256 alice_deposit_commitment = {};", public_inputs[3]);
    println!(
        "uint256 alice_transfer_commitment = {};",
        public_inputs[1 * NUM_COMMITMENTS_PER_TRANSACTION + 1]
    );
    println!(
        "uint256 bob_transfer_commitment = {};",
        public_inputs[1 * NUM_COMMITMENTS_PER_TRANSACTION + 3]
    );
    println!(
        "uint256 bob_withdraw_commitment = {};",
        public_inputs[2 * NUM_COMMITMENTS_PER_TRANSACTION + 1]
    );
    println!();
    println!("// The proof");
    println!("PrivateBalance.Groth16Proof memory proof;");
    println!("proof.pA = [{}, {}];", ax, ay);
    println!(
        "proof.pB = [[{}, {}], [{}, {}]];",
        bx.c1, bx.c0, by.c1, by.c0
    );
    println!("proof.pC = [{}, {}];", cx, cy);

    Ok(ExitCode::SUCCESS)
}

fn gen_public_keys<R: Rng + CryptoRng>(rng: &mut R) -> [ark_babyjubjub::EdwardsAffine; 3] {
    let sk1 = ark_babyjubjub::Fr::rand(rng);
    let sk2 = ark_babyjubjub::Fr::rand(rng);
    let sk3 = ark_babyjubjub::Fr::rand(rng);

    let pk1 = (ark_babyjubjub::EdwardsAffine::generator() * sk1).into_affine();
    let pk2 = (ark_babyjubjub::EdwardsAffine::generator() * sk2).into_affine();
    let pk3 = (ark_babyjubjub::EdwardsAffine::generator() * sk3).into_affine();

    println!("// MPC Public Keys");
    println!(
        "PrivateBalance.BabyJubJubElement mpc_pk1 = PrivateBalance.BabyJubJubElement(
            {},
            {}
        );",
        pk1.x, pk1.y
    );
    println!(
        "PrivateBalance.BabyJubJubElement mpc_pk2 = PrivateBalance.BabyJubJubElement(
            {},
            {}
        );",
        pk2.x, pk2.y
    );
    println!(
        "PrivateBalance.BabyJubJubElement mpc_pk3 = PrivateBalance.BabyJubJubElement(
            {},
            {}
        );",
        pk3.x, pk3.y
    );
    println!();

    [pk1, pk2, pk3]
}

fn dh_key_derivation(my_sk: &ark_babyjubjub::Fr, their_pk: ark_babyjubjub::EdwardsAffine) -> F {
    (their_pk * my_sk).into_affine().x
}

// Absorb 2, squeeze 2,  domainsep = 0x4142
// [0x80000002, 0x00000002, 0x4142]
const T2_DS: u128 = 0x80000002000000024142;
// Returns the used domain separator as a field element for the encryption
fn get_t2_ds() -> F {
    F::from(T2_DS)
}

fn sym_encrypt(key: F, mut msg: [F; 2], nonce: F) -> [F; 2] {
    let poseidon2_3 = Poseidon2::<_, 3, 5>::default();
    let ks = poseidon2_3.permutation(&[get_t2_ds(), key, nonce]);
    msg[0] += ks[1];
    msg[1] += ks[2];
    msg
}

#[expect(dead_code)]
fn sym_decrypt(key: F, mut ciphertext: [F; 2], nonce: F) -> [F; 2] {
    let poseidon2_3 = Poseidon2::<_, 3, 5>::default();
    let ks = poseidon2_3.permutation(&[get_t2_ds(), key, nonce]);
    ciphertext[0] -= ks[1];
    ciphertext[1] -= ks[2];
    ciphertext
}

fn main() -> eyre::Result<ExitCode> {
    type R = ChaCha12Rng;

    let mut seed = [0u8; 32];
    if SEED.len() > 32 {
        panic!("Seed too long");
    }
    seed[0..SEED.len()].copy_from_slice(SEED.as_bytes());
    let mut rng = R::from_seed(seed);

    let pa = TestConfig::get_transaction_batched_program_artifact()?;
    let (proof_schema, pk, cs) = r1cs::setup_r1cs(pa, &mut rng)?;
    let mut result = Vec::new();
    solidity_verifier::export_solidity_verifier(&pk.vk, &mut result)?;

    let path = format!("{}{}", ROOT, PATH);
    let mut file = File::create(path)?;
    file.write_all(&result)?;

    let keys = gen_public_keys(&mut rng);

    // Print inputs for the testcase of the solidity verifier
    test_process_mpc(&proof_schema, &cs, &pk, keys, &mut rng)?;

    Ok(ExitCode::SUCCESS)
}
