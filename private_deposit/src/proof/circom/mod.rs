pub mod deposit;
pub mod transaction;
pub mod transaction_batched;
pub mod withdraw;

use crate::proof::TestConfig;
use co_circom::CoCircomCompilerParsed;
use co_noir::Bn254;
use co_noir_to_r1cs::circom::proof_schema::CircomProofSchema;
use eyre::Context;
use rand::{CryptoRng, Rng};
use std::path::PathBuf;

impl TestConfig {
    const CIRCOM_LIB: &str = "/../circom";
    const DEPOSIT_CIRCOM: &str = "/../circom/main/deposit.circom";
    const WITHDRAW_CIRCOM: &str = "/../circom/main/withdraw.circom";
    const TRANSACTION_CIRCOM: &str = "/../circom/main/transaction.circom";
    const TRANSACTION_BATCHED_CIRCOM: &str = "/../circom/main/transaction_batched.circom";
    const DEPOSIT_R1CS: &str = "/../circom/main/deposit.r1cs";
    const WITHDRAW_R1CS: &str = "/../circom/main/withdraw.r1cs";
    const TRANSACTION_R1CS: &str = "/../circom/main/transaction.r1cs";
    const TRANSACTION_BATCHED_R1CS: &str = "/../circom/main/transaction_batched.r1cs";

    pub fn get_deposit_circom() -> eyre::Result<CoCircomCompilerParsed<ark_bn254::Fr>> {
        let lib = format!("{}{}", Self::ROOT, Self::CIRCOM_LIB);
        let circuit = format!("{}{}", Self::ROOT, Self::DEPOSIT_CIRCOM);
        CircomProofSchema::<Bn254>::read_circuit_co_circom(
            PathBuf::from(circuit),
            PathBuf::from(lib),
        )
    }

    pub fn get_deposit_proof_schema<R: Rng + CryptoRng>(
        rng: &mut R,
    ) -> eyre::Result<CircomProofSchema<Bn254>> {
        let r1cs = format!("{}{}", Self::ROOT, Self::DEPOSIT_R1CS);
        CircomProofSchema::from_r1cs_file(PathBuf::from(r1cs), rng)
            .context("while reading r1cs file")
    }

    pub fn get_withdraw_circom() -> eyre::Result<CoCircomCompilerParsed<ark_bn254::Fr>> {
        let lib = format!("{}{}", Self::ROOT, Self::CIRCOM_LIB);
        let circuit = format!("{}{}", Self::ROOT, Self::WITHDRAW_CIRCOM);
        CircomProofSchema::<Bn254>::read_circuit_co_circom(
            PathBuf::from(circuit),
            PathBuf::from(lib),
        )
    }

    pub fn get_withdraw_proof_schema<R: Rng + CryptoRng>(
        rng: &mut R,
    ) -> eyre::Result<CircomProofSchema<Bn254>> {
        let r1cs = format!("{}{}", Self::ROOT, Self::WITHDRAW_R1CS);
        CircomProofSchema::from_r1cs_file(PathBuf::from(r1cs), rng)
            .context("while reading r1cs file")
    }

    pub fn get_transaction_circom() -> eyre::Result<CoCircomCompilerParsed<ark_bn254::Fr>> {
        let lib = format!("{}{}", Self::ROOT, Self::CIRCOM_LIB);
        let circuit = format!("{}{}", Self::ROOT, Self::TRANSACTION_CIRCOM);
        CircomProofSchema::<Bn254>::read_circuit_co_circom(
            PathBuf::from(circuit),
            PathBuf::from(lib),
        )
    }

    pub fn get_transaction_proof_schema<R: Rng + CryptoRng>(
        rng: &mut R,
    ) -> eyre::Result<CircomProofSchema<Bn254>> {
        let r1cs = format!("{}{}", Self::ROOT, Self::TRANSACTION_R1CS);
        CircomProofSchema::from_r1cs_file(PathBuf::from(r1cs), rng)
            .context("while reading r1cs file")
    }

    pub fn get_transaction_batched_circom() -> eyre::Result<CoCircomCompilerParsed<ark_bn254::Fr>> {
        let lib = format!("{}{}", Self::ROOT, Self::CIRCOM_LIB);
        let circuit = format!("{}{}", Self::ROOT, Self::TRANSACTION_BATCHED_CIRCOM);
        CircomProofSchema::<Bn254>::read_circuit_co_circom(
            PathBuf::from(circuit),
            PathBuf::from(lib),
        )
    }

    pub fn get_transaction_batched_proof_schema<R: Rng + CryptoRng>(
        rng: &mut R,
    ) -> eyre::Result<CircomProofSchema<Bn254>> {
        let r1cs = format!("{}{}", Self::ROOT, Self::TRANSACTION_BATCHED_R1CS);
        CircomProofSchema::from_r1cs_file(PathBuf::from(r1cs), rng)
            .context("while reading r1cs file")
    }
}
