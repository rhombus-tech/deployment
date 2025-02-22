use ark_bls12_381::{Bls12_381, Fr as BlsScalar};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use anyhow::Result;

mod address;
mod sha256;

pub use address::AddressPrivacyCircuit;
pub use sha256::Sha256Circuit;

pub struct ZkProofSystem {
    /// Proving key for the Groth16 system
    proving_key: ProvingKey<Bls12_381>,
    /// Verification key for the Groth16 system
    verifying_key: VerifyingKey<Bls12_381>,
}

impl ZkProofSystem {
    pub fn new() -> Result<Self> {
        // Generate proving and verifying keys
        let rng = &mut ark_std::rand::thread_rng();
        
        // Create circuit with dummy inputs for setup
        let circuit = AddressPrivacyCircuit::<BlsScalar>::default();
        
        let (proving_key, verifying_key) = Groth16::<Bls12_381>::circuit_specific_setup(
            circuit,
            rng,
        )?;

        Ok(Self {
            proving_key,
            verifying_key,
        })
    }

    pub fn generate_proof(&self, address: Vec<u8>) -> Result<ZkProof> {
        let rng = &mut ark_std::rand::thread_rng();
        
        // Create circuit with actual inputs
        let circuit = AddressPrivacyCircuit::<BlsScalar>::new(address);
        
        // Generate proof
        let proof = Groth16::<Bls12_381>::prove(
            &self.proving_key,
            circuit,
            rng,
        )?;

        Ok(ZkProof { proof })
    }

    pub fn verify_proof(&self, proof: &ZkProof, public_inputs: &[Vec<u8>]) -> Result<bool> {
        // Convert public inputs to field elements
        let public_inputs: Vec<BlsScalar> = public_inputs.iter()
            .flat_map(|input| input.iter()
                .map(|&byte| BlsScalar::from(byte as u64)))
            .collect();

        // Verify the proof
        let valid = Groth16::<Bls12_381>::verify(
            &self.verifying_key,
            &public_inputs,
            &proof.proof,
        )?;

        Ok(valid)
    }
}

pub struct ZkProof {
    proof: ark_groth16::Proof<Bls12_381>,
}
