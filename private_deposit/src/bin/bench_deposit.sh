cargo build --release --bin deposit

ARGS="--seed 0 --runs 5 --num-items 100000"

RUST_LOG="warn" cargo run --release --bin deposit -- --config ./configs/party2.toml $ARGS &
RUST_LOG="warn" cargo run --release --bin deposit -- --config ./configs/party3.toml $ARGS &
cargo run --release --bin deposit -- --config ./configs/party1.toml $ARGS
