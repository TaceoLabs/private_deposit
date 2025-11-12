use alloy::{
    primitives::{Address, U256},
    providers::DynProvider,
    rpc::types::TransactionReceipt,
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
    pub async fn approve(
        &self,
        receiver: Address,
        amount: U256,
    ) -> eyre::Result<TransactionReceipt> {
        let contract = USDCToken::new(self.contract_address, self.provider.clone());

        let receipt = contract
            .approve(receiver, amount)
            .send()
            .await
            .context("while broadcasting to network")?
            .get_receipt()
            .await
            .context("while registering watcher for transaction")?;

        if receipt.status() {
            tracing::info!(
                "approve done with transaction hash: {}",
                receipt.transaction_hash
            );
        } else {
            eyre::bail!("cannot finish approve: {receipt:?}");
        }

        Ok(receipt)
    }

    pub async fn mint(&self, receiver: Address, amount: U256) -> eyre::Result<TransactionReceipt> {
        let contract = USDCToken::new(self.contract_address, self.provider.clone());

        let receipt = contract
            .mint(receiver, amount)
            .send()
            .await
            .context("while broadcasting to network")?
            .get_receipt()
            .await
            .context("while registering watcher for transaction")?;

        if receipt.status() {
            tracing::info!(
                "approve done with transaction hash: {}",
                receipt.transaction_hash
            );
        } else {
            eyre::bail!("cannot finish approve: {receipt:?}");
        }

        Ok(receipt)
    }

    pub async fn transfer(
        &self,
        receiver: Address,
        amount: U256,
    ) -> eyre::Result<TransactionReceipt> {
        let contract = USDCToken::new(self.contract_address, self.provider.clone());

        let receipt = contract
            .transfer(receiver, amount)
            .send()
            .await
            .context("while broadcasting to network")?
            .get_receipt()
            .await
            .context("while registering watcher for transaction")?;

        if receipt.status() {
            tracing::info!(
                "approve done with transaction hash: {}",
                receipt.transaction_hash
            );
        } else {
            eyre::bail!("cannot finish approve: {receipt:?}");
        }

        Ok(receipt)
    }
}
