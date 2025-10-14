use ark_ff::{PrimeField, UniformRand};
use clap::Parser;
use co_circom::{CoCircomCompilerParsed, ConstraintMatrices, ProvingKey, Rep3SharedWitness};
use co_noir::Bn254;
use co_noir_to_r1cs::{
    circom::proof_schema::CircomProofSchema, noir::r1cs, r1cs::noir_proof_schema::NoirProofScheme,
};
use eyre::{Context, eyre};
use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use mpc_core::protocols::rep3::{self, Rep3PrimeFieldShare, Rep3State, conversion::A2BType};
use mpc_net::{
    Network,
    tcp::{NetworkConfig, TcpNetwork},
};
use private_deposit::{
    data_structure::{DepositValuePlain, PrivateDeposit},
    proof::{NUM_BATCHED_TRANSACTIONS, TestConfig, transaction_batched::TransactionInput},
};
use rand::{CryptoRng, Rng};
use rand_chacha::{ChaCha12Rng, rand_core::SeedableRng};
use serde::{Deserialize, Serialize};
use std::{
    array,
    collections::BTreeMap,
    path::PathBuf,
    process::ExitCode,
    thread::sleep,
    time::{Duration, Instant},
};

const SLEEP: Duration = Duration::from_millis(200);

/// Prefix for config env variables
pub const CONFIG_ENV_PREFIX: &str = "PAYMENT_";

type F = ark_bn254::Fr;
type Curve = Bn254;
type PlainMap<F> = PrivateDeposit<F, DepositValuePlain<F>>;
type ShareMap<F> = PrivateDeposit<F, DepositValuePlain<Rep3PrimeFieldShare<F>>>;

/// Cli arguments
#[derive(Debug, Serialize, Parser)]
pub struct Cli {
    /// The path to the config file
    #[arg(long)]
    #[serde(skip_serializing_if = "::std::option::Option::is_none")]
    pub config: Option<PathBuf>,

    /// The seed for the RNG
    #[arg(short, long, default_value_t = 0)]
    pub seed: u64,

    /// The number of testruns
    #[arg(short, long, default_value_t = 10)]
    pub runs: usize,

    /// The number of elements in the map
    #[arg(short, long, default_value_t = 100)]
    pub num_items: usize,
}

/// Config
#[derive(Debug, Deserialize)]
pub struct Config {
    /// The number of testruns
    pub runs: usize,
    /// The seed for the RNG
    pub seed: u64,
    /// The number of elements in the map
    pub num_items: usize,
    /// Network config
    pub network: NetworkConfig,
}

impl Config {
    /// Parse config from file, env, cli
    pub fn parse(cli: Cli) -> Result<Self, Box<figment::error::Error>> {
        if let Some(path) = &cli.config {
            Ok(Figment::new()
                .merge(Toml::file(path))
                .merge(Env::prefixed(CONFIG_ENV_PREFIX))
                .merge(Serialized::defaults(cli))
                .extract()?)
        } else {
            Ok(Figment::new()
                .merge(Env::prefixed(CONFIG_ENV_PREFIX))
                .merge(Serialized::defaults(cli))
                .extract()?)
        }
    }
}

fn print_runtimes(times: Vec<f64>, id: usize, s: &str) {
    let mut min = f64::INFINITY;
    let mut max = 0f64;
    let mut avg = 0f64;

    let len = times.len();
    for runtime in times {
        avg += runtime;
        min = min.min(runtime);
        max = max.max(runtime);
    }
    avg /= len as f64;

    tracing::info!("{}: Party {}, {} runs", s, id, len);
    tracing::info!("\tavg: {:.2}µs", avg);
    tracing::info!("\tmin: {:.2}µs", min);
    tracing::info!("\tmax: {:.2}µs", max);
}

fn print_data(send_receive: Vec<(usize, usize)>, my_id: usize, other_id: usize, s: &str) {
    let mut min_send = f64::INFINITY;
    let mut max_send = 0f64;
    let mut avg_send = 0f64;
    let mut min_rcv = f64::INFINITY;
    let mut max_rcv = 0f64;
    let mut avg_rcv = 0f64;

    let len = send_receive.len();
    for (send, rcv) in send_receive {
        avg_send += send as f64;
        min_send = min_send.min(send as f64);
        max_send = max_send.max(send as f64);

        avg_rcv += rcv as f64;
        min_rcv = min_rcv.min(rcv as f64);
        max_rcv = max_rcv.max(rcv as f64);
    }
    avg_send /= len as f64;
    avg_rcv /= len as f64;

    tracing::info!("{}: Party {}->{}, {} runs", s, my_id, other_id, len);
    tracing::info!("\tavg: {:.2} bytes", avg_send);
    tracing::info!("\tmin: {:.2} bytes", min_send);
    tracing::info!("\tmax: {:.2} bytes", max_send);
    tracing::info!("{}: Party {}<-{}, {} runs", s, my_id, other_id, len);
    tracing::info!("\tavg: {:.2} bytes", avg_rcv);
    tracing::info!("\tmin: {:.2} bytes", min_rcv);
    tracing::info!("\tmax: {:.2} bytes", max_rcv);
}

fn main() -> eyre::Result<ExitCode> {
    type R = ChaCha12Rng;

    TestConfig::install_tracing();
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| eyre!("Could not install default rustls crypto provider"))?;

    let cli = Cli::parse();
    let config = Config::parse(cli).context("while parsing config")?;

    let mut seed = [0u8; 32];
    seed[0..8].copy_from_slice(&config.seed.to_le_bytes());
    let mut rng = R::from_seed(seed);

    benchmarks::<R>(&config, &mut rng)?;

    Ok(ExitCode::SUCCESS)
}

fn benchmarks<R: Rng + CryptoRng>(config: &Config, rng: &mut R) -> eyre::Result<ExitCode> {
    if config.network.my_id >= 3 {
        return Err(eyre!("my_id must be 0, 1 or 2"));
    }

    let num_items = std::cmp::min(
        config.num_items,
        NUM_BATCHED_TRANSACTIONS + (NUM_BATCHED_TRANSACTIONS >> 1),
    ); // We need at least NUM_BATCHED_TRANSACTIONS items to make sure we can always find a disjoint set of senders and NUM_BATCHED_TRANSACTIONS / 2 receivers. The remaining receivers are new

    tracing::info!("Sampling random Map");
    let start = Instant::now();
    let map = TestConfig::get_random_plain_map::<F, _>(num_items, rng);
    let duration = start.elapsed().as_micros() as f64;
    tracing::info!(
        "\tSampled random map with {} items in {:.2}µs",
        num_items,
        duration
    );

    tracing::info!("Sharing Map");
    let map = share_map(map, config.network.my_id, rng)?;

    // connect to network
    let nets: [TcpNetwork; NUM_BATCHED_TRANSACTIONS * 2] =
        TcpNetwork::networks(config.network.to_owned())?;

    transactions_benchmarks(&map, config, &nets, rng)?;

    Ok(ExitCode::SUCCESS)
}

fn transactions_benchmarks<R: Rng + CryptoRng>(
    map: &ShareMap<F>,
    config: &Config,
    nets: &[TcpNetwork; NUM_BATCHED_TRANSACTIONS * 2],
    rng: &mut R,
) -> eyre::Result<ExitCode> {
    tracing::info!("");
    tracing::info!("Starting transaction benchmarks");

    // Get the R1CS proof schema
    let pa = TestConfig::get_transaction_batched_program_artifact()?;
    let (proof_schema, pk, cs) = r1cs::setup_r1cs(pa, rng)?;

    transactions_with_commitments(
        map,
        config,
        nets[0..NUM_BATCHED_TRANSACTIONS].try_into().unwrap(),
        rng,
    )?;
    transactions_with_r1cs_witext(map, config, &proof_schema, nets, rng)?;
    transactions_groth16_proof(map, config, &proof_schema, &cs, &pk, nets, rng)?;

    let circom = TestConfig::get_transaction_batched_circom()?;
    let circom_proof_schema = TestConfig::get_transaction_batched_proof_schema(rng)?;

    // TODO the following witness extensions are singlethreaded!
    transactions_cocircom_witext(map, config, &circom, &nets[0], &nets[1], rng)?;
    transactions_cocircom_proof(
        map,
        config,
        &circom,
        &circom_proof_schema,
        &nets[0],
        &nets[1],
        rng,
    )?;

    Ok(ExitCode::SUCCESS)
}

fn share_map<F: PrimeField, R: Rng + CryptoRng>(
    map: PlainMap<F>,
    id: usize,
    rng: &mut R,
) -> eyre::Result<ShareMap<F>> {
    let [a, b, c] = map.share(rng);
    match id {
        0 => Ok(a),
        1 => Ok(b),
        2 => Ok(c),
        _ => Err(eyre!("my_id must be 0, 1 or 2")),
    }
}

fn share_field<F: PrimeField, R: Rng + CryptoRng>(
    x: F,
    id: usize,
    rng: &mut R,
) -> eyre::Result<Rep3PrimeFieldShare<F>> {
    let [a, b, c] = rep3::share_field_element(x, rng);
    match id {
        0 => Ok(a),
        1 => Ok(b),
        2 => Ok(c),
        _ => Err(eyre!("my_id must be 0, 1 or 2")),
    }
}

macro_rules! benchmark_blueprint {
    ($config:expr, $name:expr, $function:expr, $map:expr, $net:expr, $id_prev:expr, $id_next:expr, ($( $args:expr ),*)) => {{
        let mut times = Vec::with_capacity($config.runs);
        let mut send_receive_prev = Vec::with_capacity($config.runs);
        let mut send_receive_next = Vec::with_capacity($config.runs);

        for _ in 0..$config.runs {
            let stats_before = $net.get_connection_stats();

            let mut map = $map.to_owned();
            let start = Instant::now();

            $function(&mut map, $( $args, )*)?;

            let duration = start.elapsed().as_micros() as f64;
            times.push(duration);

            let stats_after = $net.get_connection_stats();
            let stats = stats_after.get_diff_to(&stats_before);

            send_receive_prev.push((
                stats
                    .get(&$id_prev)
                    .expect("invalid party id in stats")
                    .0,
                stats
                    .get(&$id_prev)
                    .expect("invalid party id in stats")
                    .1,
            ));
            send_receive_next.push((
                stats
                    .get(&$id_next)
                    .expect("invalid party id in stats")
                    .0,
                stats
                    .get(&$id_next)
                    .expect("invalid party id in stats")
                    .1,
            ));
        }

        sleep(SLEEP);
        print_runtimes(
            times,
            $config.network.my_id,
            $name,
        );
        print_data(
            send_receive_next,
            $config.network.my_id,
            $id_next,
            $name,
        );
        print_data(
            send_receive_prev,
            $config.network.my_id,
            $id_prev,
            $name,
        );
    }};
}

#[expect(clippy::too_many_arguments)]
fn proof_benchmark(
    witness: &Rep3SharedWitness<F>,
    cs: &ConstraintMatrices<F>,
    pk: &ProvingKey<Curve>,
    config: &Config,
    name: &str,
    net0: &TcpNetwork,
    net1: &TcpNetwork,
    protocol: &mut Rep3State,
) -> eyre::Result<ExitCode> {
    let mut times = Vec::with_capacity(config.runs);
    let mut send_receive_prev = Vec::with_capacity(config.runs);
    let mut send_receive_next = Vec::with_capacity(config.runs);

    for _ in 0..config.runs {
        let stats_before = net0.get_connection_stats();

        let witness = witness.to_owned();
        let start = Instant::now();

        let (proof, public_inputs) =
            r1cs::prove(cs, pk, witness, net0, net1).context("while generating Groth16 proof")?;

        let duration = start.elapsed().as_micros() as f64;
        times.push(duration);

        let stats_after = net0.get_connection_stats();
        let stats = stats_after.get_diff_to(&stats_before);

        send_receive_prev.push((
            stats
                .get(&(protocol.id.prev() as usize))
                .expect("invalid party id in stats")
                .0,
            stats
                .get(&(protocol.id.prev() as usize))
                .expect("invalid party id in stats")
                .1,
        ));
        send_receive_next.push((
            stats
                .get(&(protocol.id.next() as usize))
                .expect("invalid party id in stats")
                .0,
            stats
                .get(&(protocol.id.next() as usize))
                .expect("invalid party id in stats")
                .1,
        ));

        // Verify proof
        if !r1cs::verify(&pk.vk, &proof, &public_inputs)? {
            return Err(eyre!("Proof verification failed"));
        }
    }

    sleep(SLEEP);
    print_runtimes(times, config.network.my_id, name);
    print_data(
        send_receive_next,
        config.network.my_id,
        protocol.id.next() as usize,
        name,
    );
    print_data(
        send_receive_prev,
        config.network.my_id,
        protocol.id.prev() as usize,
        name,
    );

    Ok(ExitCode::SUCCESS)
}

fn get_transaction_inputs<R: Rng + CryptoRng>(
    map: &ShareMap<F>,
    id: usize,
    rng: &mut R,
) -> eyre::Result<[TransactionInput<F, Rep3PrimeFieldShare<F>>; NUM_BATCHED_TRANSACTIONS]> {
    // We make a disjoint set of senders and receivers
    let mut transaction_inputs: [TransactionInput<F, Rep3PrimeFieldShare<F>>;
        NUM_BATCHED_TRANSACTIONS] = array::from_fn(|_| TransactionInput::default());
    {
        let ordered_map = BTreeMap::from_iter(map.iter());
        let mut ordered_iter = ordered_map.into_keys();

        for (i, input) in transaction_inputs.iter_mut().enumerate() {
            let sender_key = ordered_iter.next().expect("Made sure we have enough items");
            input.sender_key = *sender_key;

            input.receiver_key = if i >= (NUM_BATCHED_TRANSACTIONS >> 1) {
                F::rand(rng)
            } else {
                let receiver_key = ordered_iter.next().expect("Made sure we have enough items");
                *receiver_key
            };
            let amount_r = share_field(F::rand(rng), id, rng)?;
            input.amount_blinding = amount_r;
            input.amount = map.read(sender_key).unwrap().amount;
        }
    }
    Ok(transaction_inputs)
}

fn transactions_with_commitments<R: Rng + CryptoRng>(
    map: &ShareMap<F>,
    config: &Config,
    nets: &[TcpNetwork; NUM_BATCHED_TRANSACTIONS],
    rng: &mut R,
) -> eyre::Result<ExitCode> {
    tracing::info!("Starting transaction_with_commitments benchmarks");
    let inputs = get_transaction_inputs(map, config.network.my_id, rng)?;

    // init MPC protocol
    let mut rep3_states = Vec::with_capacity(nets.len());
    for net in nets.iter() {
        rep3_states.push(Rep3State::new(net, A2BType::default())?);
    }

    benchmark_blueprint!(
        config,
        &format!(
            "transaction + commitment (batch={}, n={})",
            NUM_BATCHED_TRANSACTIONS, config.num_items
        ),
        PrivateDeposit::transaction_multithread_with_commitments,
        map,
        &nets[0],
        rep3_states[0].id.prev() as usize,
        rep3_states[0].id.next() as usize,
        (
            &inputs,
            nets,
            rep3_states.as_mut_slice().try_into().unwrap()
        )
    );

    Ok(ExitCode::SUCCESS)
}

fn transactions_with_r1cs_witext<R: Rng + CryptoRng>(
    map: &ShareMap<F>,
    config: &Config,
    proof_schema: &NoirProofScheme<F>,
    nets: &[TcpNetwork; NUM_BATCHED_TRANSACTIONS * 2],
    rng: &mut R,
) -> eyre::Result<ExitCode> {
    tracing::info!("Starting transaction_with_r1cs_witext benchmarks");
    let inputs = get_transaction_inputs(map, config.network.my_id, rng)?;

    // init MPC protocol
    let mut rep3_states = Vec::with_capacity(nets.len() / 2);
    for net in nets.iter().take(nets.len() / 2) {
        rep3_states.push(Rep3State::new(net, A2BType::default())?);
    }

    benchmark_blueprint!(
        config,
        &format!(
            "transaction + witext (batch={}, n={})",
            NUM_BATCHED_TRANSACTIONS, config.num_items
        ),
        PrivateDeposit::transaction_multithread_with_r1cs_witext,
        map,
        &nets[0],
        rep3_states[0].id.prev() as usize,
        rep3_states[0].id.next() as usize,
        (
            &inputs,
            proof_schema,
            nets,
            rep3_states.as_mut_slice().try_into().unwrap()
        )
    );

    Ok(ExitCode::SUCCESS)
}

fn transactions_cocircom_witext<R: Rng + CryptoRng>(
    map: &ShareMap<F>,
    config: &Config,
    circuit: &CoCircomCompilerParsed<F>,
    net0: &TcpNetwork,
    net1: &TcpNetwork,
    rng: &mut R,
) -> eyre::Result<ExitCode> {
    tracing::info!("Starting transaction_with_cocircom_witext benchmarks");
    let inputs = get_transaction_inputs(map, config.network.my_id, rng)?;

    let mut rep3_state = Rep3State::new(net0, A2BType::default())?;

    benchmark_blueprint!(
        config,
        &format!(
            "transaction + witext cocircom (batch={}, n={})",
            NUM_BATCHED_TRANSACTIONS, config.num_items
        ),
        PrivateDeposit::transaction_batched_with_cocircom_witext,
        map,
        net0,
        rep3_state.id.prev() as usize,
        rep3_state.id.next() as usize,
        (&inputs, circuit, net0, net1, &mut rep3_state)
    );

    Ok(ExitCode::SUCCESS)
}

fn transactions_groth16_proof<R: Rng + CryptoRng>(
    map: &ShareMap<F>,
    config: &Config,
    proof_schema: &NoirProofScheme<F>,
    cs: &ConstraintMatrices<F>,
    pk: &ProvingKey<Curve>,
    nets: &[TcpNetwork; NUM_BATCHED_TRANSACTIONS * 2],
    rng: &mut R,
) -> eyre::Result<ExitCode> {
    tracing::info!("Starting transaction_groth16_proof benchmarks");
    let inputs = get_transaction_inputs(map, config.network.my_id, rng)?;

    // init MPC protocol
    let mut rep3_states = Vec::with_capacity(nets.len() / 2);
    for net in nets.iter().take(nets.len() / 2) {
        rep3_states.push(Rep3State::new(net, A2BType::default())?);
    }

    // Witness extension
    let mut map = map.to_owned();
    let (_, _, witness) = map.transaction_multithread_with_r1cs_witext(
        &inputs,
        proof_schema,
        nets,
        rep3_states.as_mut_slice().try_into().unwrap(),
    )?;

    proof_benchmark(
        &witness,
        cs,
        pk,
        config,
        &format!(
            "transaction groth16 proof (batch={}, n={})",
            NUM_BATCHED_TRANSACTIONS, config.num_items
        ),
        &nets[0],
        &nets[1],
        &mut rep3_states[0],
    )?;

    Ok(ExitCode::SUCCESS)
}

fn transactions_cocircom_proof<R: Rng + CryptoRng>(
    map: &ShareMap<F>,
    config: &Config,
    circuit: &CoCircomCompilerParsed<F>,
    proof_schema: &CircomProofSchema<Curve>,
    net0: &TcpNetwork,
    net1: &TcpNetwork,
    rng: &mut R,
) -> eyre::Result<ExitCode> {
    tracing::info!("Starting transaction_cocircom_proof benchmarks");
    let inputs = get_transaction_inputs(map, config.network.my_id, rng)?;

    // init MPC protocol
    let mut rep3_state = Rep3State::new(net0, A2BType::default())?;

    // Witness extension
    let mut map = map.to_owned();
    let (_, _, witness) = map.transaction_batched_with_cocircom_witext(
        &inputs,
        circuit,
        net0,
        net1,
        &mut rep3_state,
    )?;

    proof_benchmark(
        &witness,
        &proof_schema.matrices,
        &proof_schema.pk,
        config,
        &format!(
            "transaction cocircom proof (batch={}, n={})",
            NUM_BATCHED_TRANSACTIONS, config.num_items
        ),
        net0,
        net1,
        &mut rep3_state,
    )?;

    Ok(ExitCode::SUCCESS)
}
