# Deployment on BASE Testnet

## Requirement

3 Wallets with known private key MPC, Alice and Bob:

- MPC needs enough funds to execute the smart contract.
- Alice is the sender and requires 1 ETH plus gas fees of deploy and transfer
- Bob requires gas fees of withdraw

Outcome: The 1 ETH form Alice are transmitted to BOB

## Deploy commands

### Groth16 Verifier

```forge script groth16_verifier.s.sol --broadcast --fork-url https://base-sepolia.g.alchemy.com/v2/<API_KEY> --private-key <DEPLOY_KEY>```

Transaction: <https://sepolia.basescan.org/tx/0xff7c1feeb85706bc04322afbfcd68006782f70420e1e85213ee6ae17d338bf82>
Deployed to 0x26D23457Ad7C53C28aD97aDAcA159c1d6aEadC35
Gas: 11757121

### Poseidon2

```forge script poseidon2.s.sol --broadcast --fork-url https://base-sepolia.g.alchemy.com/v2/<API_KEY> --private-key <DEPLOY_KEY>```

Transaction: <https://sepolia.basescan.org/tx/0xfc443912a2a970adbd9add667260682e09efb2316d7dfda2a6ad0ffba480cb06>
Deployed to 0x52a62aa4Ce59Cb2D997abAfD99953d5C0E68eC60
Gas: 983680

### PrivateBalance

```VERIFIER_ADDRESS=<ADDRESS> POSEIDON2_ADDRESS=<ADDRESS> MPC_ADDRESS=<MPC_ADRESS> forge script priv_balance.s.sol --broadcast --fork-url https://base-sepolia.g.alchemy.com/v2/<API_KEY> --private-key <DEPLOY_KEY>```

Transaction: <https://sepolia.basescan.org/tx/0x752d50a79e0586e05017f40527ffd2f901d1c581af7bb6dbab847408fb269b37>
Deployed to 0xF55DFe8242ec117F44Acd932adb5C233b582A04a
Gas: 2320904

## Actions

### Deposit

```PRIV_BALANCE_ADDRESS=<ADDRESS> forge script deposit.s.sol --broadcast --fork-url https://base-sepolia.g.alchemy.com/v2/<API_KEY> --private-key <ALICE_SK>```

Transaction: <https://sepolia.basescan.org/tx/0x8c499d8e9ef386af68a75309be3003285a827a67929a84b0b9f3c07892e8ac60>
Gas: 150869

### Transfer

```PRIV_BALANCE_ADDRESS=<ADDRESS> BOB_ADDRESS=<BOB_ADDRESS> forge script transfer.s.sol --broadcast --fork-url https://base-sepolia.g.alchemy.com/v2/<API_KEY> --private-key <ALICE_SK>```

Transaction: <https://sepolia.basescan.org/tx/0xb52a366b89c2effe07995535378011141e2a6783472e4c3f65d8091ae930b970>
Gas: 336856

### Withdraw

```PRIV_BALANCE_ADDRESS=<ADDRESS> forge script withdraw.s.sol --broadcast --fork-url https://base-sepolia.g.alchemy.com/v2/<API_KEY> --private-key <BOB_SK>```

Transaction: <https://sepolia.basescan.org/tx/0x7f28d76ff8eda8e980e591d939ae41e22971a2299bd9a7abe4f0170c21cf0b99>
Gas: 136838

### Process MPC

```PRIV_BALANCE_ADDRESS=<ADDRESS> forge script mpc.s.sol --broadcast --fork-url https://base-sepolia.g.alchemy.com/v2/<API_KEY> --private-key <MPC_SK>```

Transaction: <https://sepolia.basescan.org/tx/0xec559275e6a81abdb074c36d4b8d2b8f33389a1db4244cdc4298271f46f2bba0>
Gas: 3311538

### Retrieve Funds

In case something went wrong, you can retrieve the funds:

```PRIV_BALANCE_ADDRESS=<ADDRESS> forge script retrieve.s.sol --broadcast --fork-url https://base-sepolia.g.alchemy.com/v2/<API_KEY> --private-key <MPC_SK>```
