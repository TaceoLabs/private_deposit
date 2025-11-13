# Commands

```forge build```

```forge script script/conf_token.s.sol```

```forge test```

```forge test -vvv```

```forge build --silent && jq '.abi' out/conf_token.sol/ConfidentialToken.json > ConfidentialToken.json```

```forge build --silent && jq '.abi' out/token.sol/USDCToken.json > USDCToken.json```

## deploy

```forge script groth16_verifier.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80```

```forge script poseidon2.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80```

```forge script conf_token.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80```

## Notes on the solidity verifier

For reproducability and being able to easily test a circuit, we generate the ZKey randomly for a seed. Thus, the Groth16 verifier in this repos is created from an insecure ZKey!

The smart contract is generated with the deploy branch of <https://github.com/TaceoLabs/CoNoir-to-R1CS> due to size constraints of contracts
