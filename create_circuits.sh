#!/usr/bin/env bash

CIRCUITS=("private_deposit" "private_withdraw" "private_transaction")

for CIRCUIT in "${CIRCUITS[@]}"; do
  echo "Creating circuit: $CIRCUIT"
  cd noir/$CIRCUIT
  rm -rf target
  nargo compile --expression-width=1000 --bounded-codegen
  cp target/$CIRCUIT.json ../../private_deposit/data/${CIRCUIT}_circuit.json
  cd ../..
done
