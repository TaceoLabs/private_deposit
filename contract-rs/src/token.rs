use alloy::{
    primitives::{Address, TxHash, U256},
    providers::DynProvider,
    sol,
};
use eyre::Context;

// Codegen from ABI file to interact with the contract.
sol!(
    #[sol(rpc)]
    USDCToken,
    "../contracts/USDCToken.json"
);

pub struct USDCTokenContract {
    pub(crate) contract_address: Address,
    pub(crate) provider: DynProvider,
}

impl USDCTokenContract {
    pub fn new(contract_address: Address, provider: DynProvider) -> Self {
        Self {
            contract_address,
            provider,
        }
    }

    // Use U256 max value for unlimited approval
    pub async fn approve(&self, receiver: Address, amount: U256) -> eyre::Result<TxHash> {
        let contract = USDCToken::new(self.contract_address, self.provider.clone());

        let pending_tx = contract
            .approve(receiver, amount)
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
            tracing::info!("approve done with transaction hash: {tx_hash}",);
        } else {
            eyre::bail!("cannot finish approve: {receipt:?}");
        }

        Ok(tx_hash)
    }

    pub async fn mint(&self, receiver: Address, amount: U256) -> eyre::Result<TxHash> {
        let contract = USDCToken::new(self.contract_address, self.provider.clone());

        let pending_tx = contract
            .mint(receiver, amount)
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
            tracing::info!("approve done with transaction hash: {tx_hash}",);
        } else {
            eyre::bail!("cannot finish approve: {receipt:?}");
        }

        Ok(tx_hash)
    }

    pub async fn transfer(&self, receiver: Address, amount: U256) -> eyre::Result<TxHash> {
        let contract = USDCToken::new(self.contract_address, self.provider.clone());

        let pending_tx = contract
            .transfer(receiver, amount)
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
            tracing::info!("approve done with transaction hash: {tx_hash}",);
        } else {
            eyre::bail!("cannot finish approve: {receipt:?}");
        }

        Ok(tx_hash)
    }
}
