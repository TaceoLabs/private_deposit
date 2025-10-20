# Commands

```forge build```

```forge script script/priv_balance.s.sol```

```forge test```

```forge test -vvv```

## Notes on the solidity verifier

For reproducability and being able to easily test a circuit, we generate the ZKey randomly for a seed. Thus, the Groth16 verifier in this repos is created from an insecure ZKey!
