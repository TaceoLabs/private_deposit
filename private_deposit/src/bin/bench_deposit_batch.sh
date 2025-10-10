cargo build --release --bin deposit_batch

ARGS="--seed 0 --runs 5 --num-items 100000"

RUST_LOG="warn" cargo run --release --bin deposit_batch -- --config ./configs/party2.toml $ARGS &
RUST_LOG="warn" cargo run --release --bin deposit_batch -- --config ./configs/party3.toml $ARGS &
cargo run --release --bin deposit_batch -- --config ./configs/party1.toml $ARGS
