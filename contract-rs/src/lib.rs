pub mod ae;
pub mod priv_balance;

use std::array;

use alloy::{
    primitives::{Address, TxHash, U256},
    providers::{DynProvider, PendingTransaction, Provider as _},
    rpc::types::TransactionReceipt,
    transports::RpcError,
};
use ark_bn254::Bn254;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_groth16::Proof;

use crate::priv_balance::PrivateBalance::{Groth16Proof, TransactionInput};

pub(crate) type F = ark_bn254::Fr;
pub(crate) type Curve = Bn254;

// pub fn create_ciphertext

pub fn usize_to_u256(value: usize) -> U256 {
    U256::from(value)
}

pub fn u256_to_usize(value: U256) -> eyre::Result<usize> {
    let max = U256::from(usize::MAX);
    if value > max {
        eyre::bail!("U256 value is too large to fit into a usize");
    }

    let low = value.into_limbs()[0];
    let usize_value = low as usize;

    Ok(usize_value)
}

pub fn field_to_u256(field: F) -> U256 {
    U256::from_limbs(field.into_bigint().0)
}

pub fn u256_to_field(value: U256) -> eyre::Result<F> {
    let limbs = value.into_limbs();
    let bigint = <ark_bn254::Fr as PrimeField>::BigInt::new(limbs);
    F::from_bigint(bigint).ok_or_else(|| eyre::eyre!("U256 value is out of field range"))
}

pub fn u256_to_address(value: U256) -> eyre::Result<Address> {
    let bytes: [_; 32] = value.to_le_bytes();
    if bytes.iter().skip(20).any(|&b| b != 0) {
        eyre::bail!("U256 value is too large to fit into an Address");
    }
    Ok(Address::from_slice(&bytes[..20]))
}

pub fn field_to_address(field: F) -> eyre::Result<Address> {
    let u256 = field_to_u256(field);
    u256_to_address(u256)
}

impl From<Proof<Curve>> for Groth16Proof {
    fn from(proof: Proof<Curve>) -> Self {
        // Extract the proof
        let (ax, ay) = proof.a.xy().unwrap_or_default();
        let (bx, by) = proof.b.xy().unwrap_or_default();
        let (cx, cy) = proof.c.xy().unwrap_or_default();

        Self {
            pA: [
                U256::from_limbs(ax.into_bigint().0),
                U256::from_limbs(ay.into_bigint().0),
            ],
            // This is not a typo - must be c1 and then c0
            pB: [
                [
                    U256::from_limbs(bx.c1.into_bigint().0),
                    U256::from_limbs(bx.c0.into_bigint().0),
                ],
                [
                    U256::from_limbs(by.c1.into_bigint().0),
                    U256::from_limbs(by.c0.into_bigint().0),
                ],
            ],
            pC: [
                U256::from_limbs(cx.into_bigint().0),
                U256::from_limbs(cy.into_bigint().0),
            ],
        }
    }
}

async fn watch_receipt(
    provider: DynProvider,
    mut pending_tx: PendingTransaction,
) -> Result<(TransactionReceipt, TxHash), alloy::contract::Error> {
    let tx_hash = pending_tx.tx_hash().to_owned();
    // FIXME: this is a hotfix to prevent a race condition where the heartbeat would miss the
    // block the tx was mined in

    let mut interval = tokio::time::interval(provider.client().poll_interval());

    loop {
        let mut confirmed = false;

        tokio::select! {
            _ = interval.tick() => {},
            res = &mut pending_tx => {
                let _ = res?;
                confirmed = true;
            }
        }

        // try to fetch the receipt
        if let Some(receipt) = provider.get_transaction_receipt(tx_hash).await? {
            return Ok((receipt, tx_hash));
        }

        if confirmed {
            return Err(alloy::contract::Error::TransportError(RpcError::NullResp));
        }
    }
}

pub struct TransactionInputRust {
    pub action_index: Vec<usize>,
    pub commitment: Vec<F>,
}

impl TryFrom<TransactionInputRust> for TransactionInput {
    type Error = eyre::Error;

    fn try_from(input: TransactionInputRust) -> eyre::Result<Self> {
        const BATCH_SIZE: usize = 96;
        if input.action_index.len() != BATCH_SIZE || input.commitment.len() != BATCH_SIZE * 2 {
            eyre::bail!("Invalid input lengths");
        }

        let action_index = array::from_fn(|i| usize_to_u256(input.action_index[i]));
        let commitments = array::from_fn(|i| field_to_u256(input.commitment[i]));

        Ok(Self {
            action_index,
            commitments,
        })
    }
}
