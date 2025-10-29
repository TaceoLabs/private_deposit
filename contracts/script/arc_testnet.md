# Deployment on Arc Testnet

## Requirement

3 Wallets with known private key MPC, Alice and Bob:

- MPC needs enough funds to execute the smart contract.
- Alice is the sender and requires 1 USDC plus gas fees of deploy and transfer
- Bob requires gas fees of withdraw

Outcome: The 1 USDC form Alice are transmitted to BOB

## Deploy commands

### Groth16 Verifier

```forge script groth16_verifier.s.sol --broadcast --fork-url https://arc-testnet.g.alchemy.com/v2/<API_KEY> --private-key <DEPLOY_KEY>```

Transaction: <https://testnet.arcscan.app/tx/0x365370dfd12d5c9da40d73aebca2616c3e4f88a28fda623c976f08812076f62c>
Deployed to 0x26D23457Ad7C53C28aD97aDAcA159c1d6aEadC35
Gas: 11757121

### Poseidon2

```forge script poseidon2.s.sol --broadcast --fork-url https://arc-testnet.g.alchemy.com/v2/<API_KEY> --private-key <DEPLOY_KEY>```

Transaction: <https://testnet.arcscan.app/tx/0x45ba2acb3425cae0ad60b9cb372266365a9bacc672fa2caf67d63ba8d9bfb72b>
Deployed to 0x52a62aa4Ce59Cb2D997abAfD99953d5C0E68eC60
Gas: 983680

### PrivateBalance

```VERIFIER_ADDRESS=<ADDRESS> POSEIDON2_ADDRESS=<ADDRESS> MPC_ADDRESS=<MPC_ADRESS> forge script priv_balance.s.sol --broadcast --fork-url https://arc-testnet.g.alchemy.com/v2/<API_KEY> --private-key <DEPLOY_KEY>```

Transaction: <https://testnet.arcscan.app/tx/0xca2bcfe13eba5cba76beee25590a181ca4f24dc074a59941f177ec49c75a3749>
Deployed to 0x544684976c936F691D67165D37233FC4f78Ff4d5
Gas: 8362043

## Actions

### Deposit

```PRIV_BALANCE_ADDRESS=<ADDRESS> forge script deposit.s.sol --broadcast --fork-url https://arc-testnet.g.alchemy.com/v2/<API_KEY> --private-key <ALICE_SK>```

Transaction: <https://testnet.arcscan.app/tx/0x49a99ff68bd6e8e570c8c54fb198af5e0d907e0fb329c777e8379935e6491a36>
Gas: 151982

### Transfer

```PRIV_BALANCE_ADDRESS=<ADDRESS> BOB_ADDRESS=<BOB_ADDRESS> forge script transfer.s.sol --broadcast --fork-url https://arc-testnet.g.alchemy.com/v2/<API_KEY> --private-key <ALICE_SK>```

Transaction: <https://testnet.arcscan.app/tx/0x8bab3d70a6824355d32a228fcf083e0f4c0acf43defbc6d042c286ea44f05220>
Gas: 334993

### Withdraw

```PRIV_BALANCE_ADDRESS=<ADDRESS> forge script withdraw.s.sol --broadcast --fork-url https://arc-testnet.g.alchemy.com/v2/<API_KEY> --private-key <BOB_SK>```

Transaction: <https://testnet.arcscan.app/tx/0x9d93f88b7388d974ff904900eaa5d63a816fce474da00f4e7ee288a06393094d>
Gas: 131999

### Process MPC

```PRIV_BALANCE_ADDRESS=<ADDRESS> forge script mpc.s.sol --broadcast --fork-url https://arc-testnet.g.alchemy.com/v2/<API_KEY> --private-key <MPC_SK>```

Transaction: <https://testnet.arcscan.app/tx/0x12afba55c5875353f24d0a9627adebe43aa7d2c52475b68853971a833e219b2a>
Gas: 3311560

### Retrieve Funds

In case something went wrong, you can retrieve the funds:

```PRIV_BALANCE_ADDRESS=<ADDRESS> forge script retrieve.s.sol --broadcast --fork-url https://arc-testnet.g.alchemy.com/v2/<API_KEY> --private-key <MPC_SK>```
