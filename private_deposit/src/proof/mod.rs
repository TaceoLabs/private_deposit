pub mod deposit;

use mpc_core::protocols::rep3::Rep3State;
use mpc_net::Network;

pub struct Rep3NetworkState<'a, 'b, 'c, N: Network> {
    net0: &'a N,
    net1: &'b N,
    rep3_state: &'c mut Rep3State,
}
