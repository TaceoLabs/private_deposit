#!/usr/bin/env bash

# ANVIL needs to be running

PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

COMMAND="forge script"
FLAGS="--broadcast --fork-url http://127.0.0.1:8545"

MPC_ADDRESS="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
ALICE="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
BOB="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"

ALICE_PRIVATE_KEY="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
BOB_PRIVATE_KEY="0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"

forge clean

# DEPLOY CONTRACTS
cd deploy
echo "############################################"
echo "Deploying Groth16 verifier..."
out=$($COMMAND groth16_verifier.s.sol $FLAGS --private-key $PRIVATE_KEY 2>&1)
found=${out#*"deployed to: "}
v_address=${found%%$'\n'*}
echo "Deployed at $v_address"

echo "############################################"
echo "Deploying Poseidon2..."
out=$($COMMAND poseidon2.s.sol $FLAGS --private-key $PRIVATE_KEY 2>&1)
found=${out#*"deployed to: "}
p_address=${found%%$'\n'*}
echo "Deployed at $p_address"

echo "############################################"
echo "Deploying Token..."
out=$($COMMAND token.s.sol $FLAGS --private-key $PRIVATE_KEY 2>&1)
found=${out#*"deployed to: "}
t_address=${found%%$'\n'*}
echo "Deployed at $t_address"

echo "############################################"
echo "Deploying PrivateBalance..."
out=$(VERIFIER_ADDRESS=$v_address POSEIDON2_ADDRESS=$p_address TOKEN_ADDRESS=$t_address MPC_ADDRESS=$MPC_ADDRESS $COMMAND priv_balance.s.sol $FLAGS --private-key $PRIVATE_KEY 2>&1)
found=${out#*"deployed to: "}
address=${found%%$'\n'*}
echo "Deployed at $address"
cd ..

# Setup tokens
cd test
echo "############################################"
echo "Giving Balance to Alice..."
out=$(TOKEN_ADDRESS=$t_address RECEIVER_ADDRESS=$ALICE $COMMAND mint_token.s.sol $FLAGS --private-key $PRIVATE_KEY 2>&1)

echo "############################################"
echo "Approve Alice..."
out=$(PRIV_BALANCE_ADDRESS=$address TOKEN_ADDRESS=$t_address $COMMAND approve_token.s.sol $FLAGS --private-key $ALICE_PRIVATE_KEY 2>&1)
cd ..

# Register actions
cd test
echo "############################################"
echo "Registering deposit..."
out=$(PRIV_BALANCE_ADDRESS=$address $COMMAND deposit.s.sol $FLAGS --private-key $ALICE_PRIVATE_KEY 2>&1)
found=${out#*"at index "}
index=${found%%$'\n'*}
echo "Registered at index $index"

echo "############################################"
echo "Registering transfer..."
out=$(PRIV_BALANCE_ADDRESS=$address BOB_ADDRESS=$BOB $COMMAND transfer.s.sol $FLAGS --private-key $ALICE_PRIVATE_KEY 2>&1)
found=${out#*"at index "}
index=${found%%$'\n'*}
echo "Registered at index $index"

echo "############################################"
echo "Registering withdraw..."
out=$(PRIV_BALANCE_ADDRESS=$address $COMMAND withdraw.s.sol $FLAGS --private-key $BOB_PRIVATE_KEY 2>&1)
found=${out#*"at index "}
index=${found%%$'\n'*}
echo "Registered at index $index"
cd ..

# Process MPC
cd test
echo "############################################"
echo "Processing MPC..."
out=$(PRIV_BALANCE_ADDRESS=$address $COMMAND mpc.s.sol $FLAGS --private-key $PRIVATE_KEY 2>&1)
echo "Done"
cd ..
