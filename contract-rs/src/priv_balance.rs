use alloy::{
    network::EthereumWallet,
    primitives::{Address, TxHash},
    providers::{DynProvider, Provider as _, ProviderBuilder, WsConnect},
    sol,
};
use eyre::Context;

use crate::{
    F,
    priv_balance::PrivateBalance::{ActionQuery, Groth16Proof, TransactionInput},
};

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

    pub async fn retrieve_funds(&self) -> eyre::Result<TxHash> {
        let contract = PrivateBalance::new(self.contract_address, self.provider.clone());

        let pending_tx = contract
            .retrieveFunds()
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
            tracing::info!("round 1 done with transaction hash: {tx_hash}",);
        } else {
            eyre::bail!("cannot finish transaction: {receipt:?}");
        }

        Ok(tx_hash)
    }

    pub async fn deposit(&self, amount: F) -> eyre::Result<TxHash> {
        let contract = PrivateBalance::new(self.contract_address, self.provider.clone());

        let pending_tx = contract
            .deposit()
            .value(crate::field_to_u256(amount))
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

    pub async fn transfer(&self, to: F, amount: F) -> eyre::Result<TxHash> {
        let contract = PrivateBalance::new(self.contract_address, self.provider.clone());

        let pending_tx = contract
            .transfer(crate::field_to_address(to)?, crate::field_to_u256(amount))
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
            tracing::info!("transfer done with transaction hash: {tx_hash}",);
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
            tracing::info!("remove action done with transaction hash: {tx_hash}",);
        } else {
            eyre::bail!("cannot finish transaction: {receipt:?}");
        }

        Ok(tx_hash)
    }

    pub async fn read_queue(&self) -> eyre::Result<(Vec<usize>, Vec<ActionQuery>)> {
        const BATCH_SIZE: usize = 96;

        let contract = PrivateBalance::new(self.contract_address, self.provider.clone());
        let res = contract
            .read_queue()
            .call()
            .await
            .context("while calling get_action_at_index")?;

        if res._0.len() != res._1.len() {
            eyre::bail!("mismatched lengths in read_queue");
        }
        if res._0.len() > BATCH_SIZE {
            eyre::bail!("too many entries in read_queue");
        }

        let indices = res
            ._0
            .into_iter()
            .map(crate::u256_to_usize)
            .collect::<eyre::Result<Vec<usize>>>()?;

        Ok((indices, res._1))
    }
}
