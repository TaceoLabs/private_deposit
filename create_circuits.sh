#!/usr/bin/env bash

CIRCUITS=("private_deposit" "private_withdraw" "private_transaction" "private_transaction_batched")

for CIRCUIT in "${CIRCUITS[@]}"; do
  echo "Creating circuit: $CIRCUIT"
  cd noir/$CIRCUIT
  rm -rf target
  nargo compile --expression-width=1000 --bounded-codegen
  cp target/$CIRCUIT.json ../../private_deposit/data/${CIRCUIT}.json
  cd ../..
done

CIRCOM_CIRCUITS=("deposit" "withdraw" "transaction" "transaction_batched")

cd circom/main
for CIRCUIT in "${CIRCOM_CIRCUITS[@]}"; do
    rm -rf ${CIRCUIT}.r1cs
    circom -l .. --O2 --r1cs $CIRCUIT.circom
done
cd ../..
