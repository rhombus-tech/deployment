use ark_bn254::{Bn254, Fr};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey, Proof};
use ark_std::rand::{RngCore, CryptoRng};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, SerializationError};
use ark_snark::SNARK;
use anyhow::{Result, anyhow};

/// Generate proving key for a circuit
pub fn generate_proving_key<C, R>(
    circuit: C,
    rng: &mut R,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>)>
where
    C: ConstraintSynthesizer<Fr>,
    R: RngCore + CryptoRng,
{
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, rng)
        .map_err(|e| anyhow!("Setup error: {:?}", e))?;
    Ok((pk, vk))
}

/// Generate a proof for a circuit
pub fn generate_proof<C, R>(
    circuit: C,
    proving_key: &ProvingKey<Bn254>,
    rng: &mut R,
) -> Result<Vec<u8>>
where
    C: ConstraintSynthesizer<Fr>,
    R: RngCore + CryptoRng,
{
    let proof = Groth16::<Bn254>::prove(proving_key, circuit, rng)
        .map_err(|e| anyhow!("Proving error: {:?}", e))?;
    let mut proof_bytes = Vec::new();
    proof.serialize(&mut proof_bytes)
        .map_err(|e| anyhow!("Serialization error: {:?}", e))?;
    Ok(proof_bytes)
}

/// Deserialize a proof from bytes
pub fn deserialize_proof(proof_bytes: &[u8]) -> Result<Proof<Bn254>> {
    Proof::deserialize(proof_bytes)
        .map_err(|e| anyhow!("Deserialization error: {:?}", e))
}

/// Verify a proof
pub fn verify_proof(
    verifying_key: &VerifyingKey<Bn254>,
    proof_bytes: &[u8],
    public_inputs: &[Fr],
) -> Result<bool>
{
    let proof = deserialize_proof(proof_bytes)?;
    Groth16::<Bn254>::verify(verifying_key, public_inputs, &proof)
        .map_err(|e| anyhow!("Verification error: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::thread_rng;
    use crate::circuit_impl::{PCDCircuit, DataPredicateCircuit};
    use ark_std::marker::PhantomData;
    use ethers::types::Bytes;

    #[test]
    fn test_simple_circuit() -> Result<(), anyhow::Error> {
        let mut rng = thread_rng();

        // Create a simple circuit that checks if two values are equal
        let prev_state = vec![Fr::from(1u32)];
        let curr_state = vec![Fr::from(2u32)];
        
        let circuit = PCDCircuit {
            bytecode: Bytes::from(vec![0u8]),
            prev_state: Some(prev_state.clone()),
            curr_state: curr_state.clone(),
            _field: PhantomData,
        };
        
        // Generate proving and verifying keys
        let (pk, vk) = generate_proving_key(circuit.clone(), &mut rng)?;
        
        // Generate a proof
        let proof_bytes = generate_proof(circuit, &pk, &mut rng)?;
        
        // Verify the proof
        let is_valid = verify_proof(&vk, &proof_bytes, &curr_state)?;
        
        assert!(is_valid, "Proof verification should succeed");
        
        Ok(())
    }
    
    #[test]
    fn test_data_predicate() -> Result<(), anyhow::Error> {
        let mut rng = thread_rng();
        
        // Create a simple data predicate circuit
        let data = vec![1u8, 2u8, 3u8];
        let predicate = vec![4u8, 5u8, 6u8];
        
        let circuit = DataPredicateCircuit {
            data: data.clone(),
            predicate: predicate.clone(),
            _field: PhantomData,
        };
        
        // Generate proving and verifying keys
        let (pk, vk) = generate_proving_key(circuit.clone(), &mut rng)?;
        
        // Generate a proof
        let proof_bytes = generate_proof(circuit, &pk, &mut rng)?;
        
        // Create public inputs from the first byte of data and predicate
        let public_inputs = vec![Fr::from(data[0] as u64), Fr::from(predicate[0] as u64)];
        
        // Verify the proof
        let is_valid = verify_proof(&vk, &proof_bytes, &public_inputs)?;
        
        assert!(is_valid, "Proof verification should succeed");
        
        Ok(())
    }
}
