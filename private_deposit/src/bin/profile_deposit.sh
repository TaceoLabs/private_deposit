cargo build --profile profiling --bin deposit

ARGS="--seed 0 --runs 5 --num-items 100000"
BIN="../../../target/profiling/deposit"

$BIN --config ./configs/party2.toml $ARGS &
$BIN --config ./configs/party3.toml $ARGS &
flamegraph -- $BIN --config ./configs/party1.toml $ARGS
