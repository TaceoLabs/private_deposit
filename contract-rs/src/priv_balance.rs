use crate::{
    F,
    priv_balance::PrivateBalance::{
        ActionQuery, BabyJubJubElement, Ciphertext, Groth16Proof, TransactionInput,
    },
};
use alloy::{
    network::EthereumWallet,
    primitives::{Address, TxHash, U256},
    providers::{DynProvider, Provider as _, ProviderBuilder, WsConnect},
    sol,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{UniformRand, Zero};
use eyre::Context;
use rand::{CryptoRng, Rng};

// Codegen from ABI file to interact with the contract.
sol!(
    #[sol(rpc)]
    PrivateBalance,
    "../contracts/PrivateBalance.json"
);

pub struct PrivateBalanceContract {
    pub(crate) contract_address: Address,
    pub(crate) provider: DynProvider,
}

impl PrivateBalanceContract {
    pub fn new(contract_address: Address, provider: DynProvider) -> Self {
        Self {
            contract_address,
            provider,
        }
    }

    // Returns additive shares of the decrypted amount and randomness for the given party index
    pub fn decrypt_share(
        ciphertext: Ciphertext,
        my_sk: ark_babyjubjub::Fr,
        my_index: usize,
    ) -> eyre::Result<[F; 2]> {
        if my_index >= 3 {
            eyre::bail!("invalid party index for decryption share");
        }
        let sender_pk = ark_babyjubjub::EdwardsAffine::new(
            crate::u256_to_field(ciphertext.sender_pk.x)?,
            crate::u256_to_field(ciphertext.sender_pk.y)?,
        );
        let dh_key = crate::ae::dh_key_derivation(&my_sk, sender_pk);

        let decrypted = crate::ae::sym_decrypt(
            dh_key,
            [
                crate::u256_to_field(ciphertext.amount[my_index])?,
                crate::u256_to_field(ciphertext.r[my_index])?,
            ],
            F::zero(),
        );
        Ok(decrypted)
    }

    pub fn encrypt_shares<R: Rng + CryptoRng>(
        amount_shares: [F; 3],
        rand_shares: [F; 3],
        mpc_pk: &[ark_babyjubjub::EdwardsAffine; 3],
        rng: &mut R,
    ) -> Ciphertext {
        let sk = ark_babyjubjub::Fr::rand(rng);
        let pk = (ark_babyjubjub::EdwardsAffine::generator() * sk).into_affine();

        let mut result = Ciphertext {
            amount: [U256::default(); 3],
            r: [U256::default(); 3],
            sender_pk: BabyJubJubElement {
                x: crate::field_to_u256(pk.x),
                y: crate::field_to_u256(pk.y),
            },
        };

        for i in 0..3 {
            let dh_key = crate::ae::dh_key_derivation(&sk, mpc_pk[i]);
            let msg = [amount_shares[i], rand_shares[i]];
            let encrypted = crate::ae::sym_encrypt(dh_key, msg, F::zero());
            result.amount[i] = crate::field_to_u256(encrypted[0]);
            result.r[i] = crate::field_to_u256(encrypted[1]);
        }

        result
    }

    pub async fn init(
        rpc_url: &str,
        contract_address: Address,
        wallet: EthereumWallet,
    ) -> eyre::Result<Self> {
        // Create the provider.
        let ws = WsConnect::new(rpc_url); // rpc-url of anvil
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_ws(ws)
            .await
            .context("while connecting to RPC")?;

        Ok(Self {
            contract_address,
            provider: provider.erased(),
        })
    }

    pub async fn get_balance_commitment(&self, user: F) -> eyre::Result<F> {
        let contract = PrivateBalance::new(self.contract_address, self.provider.clone());
        let commitment = contract
            .getBalanceCommitment(crate::field_to_address(user)?)
            .call()
            .await
            .context("while calling get_balance_commitment")?;

        crate::u256_to_field(commitment)
    }

    pub async fn get_action_at_index(&self, index: usize) -> eyre::Result<ActionQuery> {
        let contract = PrivateBalance::new(self.contract_address, self.provider.clone());
        contract
            .getActionAtIndex(crate::usize_to_u256(index))
            .call()
            .await
            .context("while calling get_action_at_index")
    }

    pub async fn get_action_queue_size(&self) -> eyre::Result<usize> {
        let contract = PrivateBalance::new(self.contract_address, self.provider.clone());
        let size = contract
            .getActionQueueSize()
            .call()
            .await
            .context("while calling get_action_queue_size")?;

        crate::u256_to_usize(size)
    }

    pub async fn retrieve_funds(&self, receiver: Address) -> eyre::Result<TxHash> {
        let contract = PrivateBalance::new(self.contract_address, self.provider.clone());

        let pending_tx = contract
            .retrieveFunds(receiver)
            .send()
            .await
            .context("while broadcasting to network")?
            .register()
            .await
            .context("while registering watcher for transaction")?;

        let (receipt, tx_hash) = crate::watch_receipt(self.provider.clone(), pending_tx)
            .await
            .context("while waiting for receipt")?;
        if receipt.status() {
            tracing::info!("retrieve funds done with transaction hash: {tx_hash}",);
        } else {
            eyre::bail!("cannot finish transaction: {receipt:?}");
        }

        Ok(tx_hash)
    }

    pub async fn deposit(&self, amount: F) -> eyre::Result<TxHash> {
        let contract = PrivateBalance::new(self.contract_address, self.provider.clone());

        let pending_tx = contract
            .deposit(crate::field_to_u256(amount))
            .send()
            .await
            .context("while broadcasting to network")?
            .register()
            .await
            .context("while registering watcher for transaction")?;

        let (receipt, tx_hash) = crate::watch_receipt(self.provider.clone(), pending_tx)
            .await
            .context("while waiting for receipt")?;
        if receipt.status() {
            tracing::info!("deposit done with transaction hash: {tx_hash}",);
        } else {
            eyre::bail!("cannot finish transaction: {receipt:?}");
        }

        Ok(tx_hash)
    }

    pub async fn withdraw(&self, amount: F) -> eyre::Result<TxHash> {
        let contract = PrivateBalance::new(self.contract_address, self.provider.clone());

        let pending_tx = contract
            .withdraw(crate::field_to_u256(amount))
            .send()
            .await
            .context("while broadcasting to network")?
            .register()
            .await
            .context("while registering watcher for transaction")?;

        let (receipt, tx_hash) = crate::watch_receipt(self.provider.clone(), pending_tx)
            .await
            .context("while waiting for receipt")?;
        if receipt.status() {
            tracing::info!("withdraw done with transaction hash: {tx_hash}",);
        } else {
            eyre::bail!("cannot finish transaction: {receipt:?}");
        }

        Ok(tx_hash)
    }

    pub async fn get_mpc_keys(&self) -> eyre::Result<[ark_babyjubjub::EdwardsAffine; 3]> {
        let contract = PrivateBalance::new(self.contract_address, self.provider.clone());
        let key1 = contract
            .mpc_pk1()
            .call()
            .await
            .context("while calling get_balance_commitment")?;
        let key2 = contract
            .mpc_pk2()
            .call()
            .await
            .context("while calling get_balance_commitment")?;
        let key3 = contract
            .mpc_pk3()
            .call()
            .await
            .context("while calling get_balance_commitment")?;

        let key1 = ark_babyjubjub::EdwardsAffine::new(
            crate::u256_to_field(key1.x)?,
            crate::u256_to_field(key1.y)?,
        );
        let key2 = ark_babyjubjub::EdwardsAffine::new(
            crate::u256_to_field(key2.x)?,
            crate::u256_to_field(key2.y)?,
        );
        let key3 = ark_babyjubjub::EdwardsAffine::new(
            crate::u256_to_field(key3.x)?,
            crate::u256_to_field(key3.y)?,
        );

        Ok([key1, key2, key3])
    }

    pub async fn transfer_with_sender(
        &self,
        to: Address,
        from: Address,
        amount: F,
        ciphertext: Ciphertext,
    ) -> eyre::Result<TxHash> {
        let contract = PrivateBalance::new(self.contract_address, self.provider.clone());

        let pending_tx = contract
            .transfer(to, crate::field_to_u256(amount), ciphertext)
            .from(from)
            .send()
            .await
            .context("while broadcasting to network")?
            .register()
            .await
            .context("while registering watcher for transaction")?;

        let (receipt, tx_hash) = crate::watch_receipt(self.provider.clone(), pending_tx)
            .await
            .context("while waiting for receipt")?;
        if receipt.status() {
            tracing::info!(
                "transfer done with transaction hash: {tx_hash:?}, gas used: {}",
                receipt.gas_used
            );
        } else {
            eyre::bail!("cannot finish transaction: {receipt:?}");
        }

        Ok(tx_hash)
    }

    pub async fn transfer(
        &self,
        to: Address,
        amount: F,
        ciphertext: Ciphertext,
    ) -> eyre::Result<TxHash> {
        let contract = PrivateBalance::new(self.contract_address, self.provider.clone());

        let pending_tx = contract
            .transfer(to, crate::field_to_u256(amount), ciphertext)
            .send()
            .await
            .context("while broadcasting to network")?
            .register()
            .await
            .context("while registering watcher for transaction")?;

        let (receipt, tx_hash) = crate::watch_receipt(self.provider.clone(), pending_tx)
            .await
            .context("while waiting for receipt")?;
        if receipt.status() {
            tracing::debug!("transfer done with transaction hash: {tx_hash:?}",);
        } else {
            eyre::bail!("cannot finish transaction: {receipt:?}");
        }

        Ok(tx_hash)
    }

    pub async fn transfer_batched(
        &self,
        from: &[Address],
        to: &[Address],
        amount: &[F],
        // ciphertext: &[Ciphertext],
    ) -> eyre::Result<TxHash> {
        assert_eq!(from.len(), to.len());
        assert_eq!(from.len(), amount.len());
        // assert_eq!(from.len(), ciphertext.len());
        let contract = PrivateBalance::new(self.contract_address, self.provider.clone());

        let pending_tx = contract
            .transferBatch(
                from.to_vec(),
                to.to_vec(),
                amount.iter().map(|x| crate::field_to_u256(*x)).collect(),
                // ciphertext.to_vec(),
            )
            .send()
            .await
            .context("while broadcasting to network")?
            .register()
            .await
            .context("while registering watcher for transaction")?;

        let (receipt, tx_hash) = crate::watch_receipt(self.provider.clone(), pending_tx)
            .await
            .context("while waiting for receipt")?;
        if receipt.status() {
            tracing::info!(
                "transferBatch done with transaction hash: {tx_hash:?}, gas_used: {}",
                receipt.gas_used
            );
        } else {
            eyre::bail!("cannot finish transaction: {receipt:?}");
        }

        Ok(tx_hash)
    }

    pub async fn remove_action_at_index(&self, index: usize) -> eyre::Result<TxHash> {
        let contract = PrivateBalance::new(self.contract_address, self.provider.clone());

        let pending_tx = contract
            .removeActionAtIndex(crate::usize_to_u256(index))
            .send()
            .await
            .context("while broadcasting to network")?
            .register()
            .await
            .context("while registering watcher for transaction")?;

        let (receipt, tx_hash) = crate::watch_receipt(self.provider.clone(), pending_tx)
            .await
            .context("while waiting for receipt")?;
        if receipt.status() {
            tracing::info!("remove action done with transaction hash: {tx_hash}",);
        } else {
            eyre::bail!("cannot finish transaction: {receipt:?}");
        }

        Ok(tx_hash)
    }

    pub async fn remove_all_open_actions(&self) -> eyre::Result<TxHash> {
        let contract = PrivateBalance::new(self.contract_address, self.provider.clone());

        let pending_tx = contract
            .removeAllOpenActions()
            .send()
            .await
            .context("while broadcasting to network")?
            .register()
            .await
            .context("while registering watcher for transaction")?;

        let (receipt, tx_hash) = crate::watch_receipt(self.provider.clone(), pending_tx)
            .await
            .context("while waiting for receipt")?;
        if receipt.status() {
            tracing::info!("remove all actions done with transaction hash: {tx_hash}",);
        } else {
            eyre::bail!("cannot finish transaction: {receipt:?}");
        }

        Ok(tx_hash)
    }

    pub async fn process_mpc(
        &self,
        inputs: TransactionInput,
        proof: Groth16Proof,
    ) -> eyre::Result<TxHash> {
        let contract = PrivateBalance::new(self.contract_address, self.provider.clone());

        let pending_tx = contract
            .processMPC(inputs, proof)
            .send()
            .await
            .context("while broadcasting to network")?
            .register()
            .await
            .context("while registering watcher for transaction")?;

        let (receipt, tx_hash) = crate::watch_receipt(self.provider.clone(), pending_tx)
            .await
            .context("while waiting for receipt")?;
        if receipt.status() {
            tracing::info!(
                "Process MPC done with transaction hash: {tx_hash}, gas_used: {}",
                receipt.gas_used
            );
        } else {
            eyre::bail!("cannot finish transaction: {receipt:?}");
        }

        Ok(tx_hash)
    }

    pub async fn withelist_addresses_for_demo(
        &self,
        addresses: Vec<Address>,
    ) -> eyre::Result<TxHash> {
        let contract = PrivateBalance::new(self.contract_address, self.provider.clone());

        let pending_tx = contract
            .whitelistForDemo(addresses)
            .send()
            .await
            .context("while broadcasting to network")?
            .register()
            .await
            .context("while registering watcher for whitelist")?;

        let (receipt, tx_hash) = crate::watch_receipt(self.provider.clone(), pending_tx)
            .await
            .context("while waiting for receipt")?;
        if receipt.status() {
            tracing::info!("whitelist done with transaction hash: {tx_hash}",);
        } else {
            eyre::bail!("cannot finish transaction: {receipt:?}");
        }

        Ok(tx_hash)
    }

    pub async fn set_balances_for_demo(
        &self,
        addresses: Vec<Address>,
        balances: Vec<U256>,
        total_balances_amount: F,
    ) -> eyre::Result<TxHash> {
        let contract = PrivateBalance::new(self.contract_address, self.provider.clone());

        let pending_tx = contract
            .setBalancesForDemo(
                addresses,
                balances,
                crate::field_to_u256(total_balances_amount),
            )
            .send()
            .await
            .context("while broadcasting to network")?
            .register()
            .await
            .context("while registering watcher for set_balance")?;

        let (receipt, tx_hash) = crate::watch_receipt(self.provider.clone(), pending_tx)
            .await
            .context("while waiting for receipt")?;
        if receipt.status() {
            tracing::info!("set_balance done with transaction hash: {tx_hash}",);
        } else {
            eyre::bail!("cannot finish transaction: {receipt:?}");
        }

        Ok(tx_hash)
    }

    pub async fn read_queue(
        &self,
        num_items: usize,
    ) -> eyre::Result<(Vec<usize>, Vec<ActionQuery>, Vec<Ciphertext>)> {
        let contract = PrivateBalance::new(self.contract_address, self.provider.clone());
        let res = contract
            .read_queue(crate::usize_to_u256(num_items))
            .call()
            .await
            .context("while calling read_queue")?;

        if res._0.len() != res._1.len() {
            eyre::bail!("mismatched lengths in read_queue");
        }
        if res._0.len() != res._2.len() {
            eyre::bail!("mismatched lengths in read_queue");
        }

        let indices = res
            ._0
            .into_iter()
            .map(crate::u256_to_usize)
            .collect::<eyre::Result<Vec<usize>>>()?;

        Ok((indices, res._1, res._2))
    }

    pub async fn get_ciphertext_at_index(&self, index: usize) -> eyre::Result<Ciphertext> {
        let contract = PrivateBalance::new(self.contract_address, self.provider.clone());
        contract
            .getCiphertextAtIndex(crate::usize_to_u256(index))
            .call()
            .await
            .context("while calling get_ciphertext_at_index")
    }
}
