use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use anyhow::{anyhow, Result};

// Define the to_bytes! macro
#[macro_export]
macro_rules! to_bytes {
    ($x:expr) => {{
        let mut buf = Vec::new();
        $x.write(&mut buf).map_err(|e| anyhow!("Serialization error: {:?}", e))?;
        Ok::<Vec<u8>, anyhow::Error>(buf)
    }};
}

/// Generate proving key for a circuit
pub fn generate_proving_key<C, R>(
    circuit: C,
    rng: &mut R,
) -> Result<ProvingKey<Bn254>, anyhow::Error>
where
    C: ConstraintSynthesizer<Fr>,
    R: RngCore + CryptoRng,
{
    Groth16::<Bn254>::circuit_specific_setup(circuit, rng)
        .map(|pk| pk.0)
        .map_err(|e| anyhow!("Setup error: {:?}", e))
}

/// Generate a proof for a circuit
pub fn generate_proof<C, R>(
    circuit: C,
    pk: &ProvingKey<Bn254>,
    rng: &mut R,
) -> Result<Vec<u8>, anyhow::Error>
where
    C: ConstraintSynthesizer<Fr>,
    R: RngCore + CryptoRng,
{
    let proof = Groth16::<Bn254>::prove(pk, circuit, rng)
        .map_err(|e| anyhow!("Proving error: {:?}", e))?;
    
    serialize_proof(&proof)
}

/// Verify a proof
pub fn verify_proof<F: PrimeField, C: ConstraintSynthesizer<F>>(
    circuit: C,
    proof: &Proof<Bn254>,
    verifying_key: &VerifyingKey<Bn254>,
    public_inputs: Option<Vec<F>>,
) -> Result<bool, anyhow::Error> {
    // Get public inputs from circuit if not provided
    let inputs = if let Some(inputs) = public_inputs {
        println!("Debug: Using provided public inputs: {} elements", inputs.len());
        inputs
    } else {
        println!("Debug: Generating public inputs from circuit");
        let cs = ConstraintSystem::<F>::new_ref();
        circuit.generate_constraints(cs.clone())
            .map_err(|e| anyhow!("Constraint generation error: {:?}", e))?;
        
        // Extract public inputs from constraint system
        let public_inputs = if let Some(cs_ref) = cs.borrow().as_ref() {
            cs_ref.instance_assignment.to_vec()
        } else {
            return Err(anyhow!("Failed to borrow constraint system"));
        };
        println!("Debug: Generated {} public inputs from circuit", public_inputs.len());
        for (i, input) in public_inputs.iter().enumerate() {
            println!("Debug: Circuit public input {}: {:?}", i, input);
        }
        public_inputs
    };

    // Convert to Fr
    let mut inputs_fr = Vec::new();
    
    // Always add F::one() as the first public input if it's not already there
    let one_bytes = to_bytes!(F::one())?;
    let one_fr: Fr = Fr::from_le_bytes_mod_order(&one_bytes);
    
    // Check if the first input is already F::one()
    if inputs.is_empty() || to_bytes!(inputs[0])? != one_bytes {
        println!("Debug: Adding F::one() as first public input");
        inputs_fr.push(one_fr);
    }
    
    // Add the rest of the inputs
    for x in inputs.iter() {
        let bytes: Vec<u8> = to_bytes!(x)?;
        inputs_fr.push(Fr::from_le_bytes_mod_order(&bytes));
    }
    
    println!("Debug: Verifying with {} public inputs (Fr)", inputs_fr.len());
    for (i, input) in inputs_fr.iter().enumerate() {
        println!("Debug: Public input {}: {:?}", i, input);
    }
    
    println!("Debug: Verifying key gamma_abc size: {}", verifying_key.gamma_abc_g1.len());
    println!("Debug: Proof components: a={:?}, b={:?}, c={:?}", proof.a, proof.b, proof.c);

    match Groth16::<Bn254>::verify(verifying_key, &inputs_fr, &proof) {
        Ok(result) => {
            println!("Debug: Verification result: {}", result);
            Ok(result)
        },
        Err(e) => {
            println!("Debug: Verification error: {:?}", e);
            Err(anyhow!("Verification error: {:?}", e))
        }
    }
}

/// Serialize a proof to bytes
pub fn serialize_proof(proof: &Proof<Bn254>) -> Result<Vec<u8>, anyhow::Error> {
    let mut proof_bytes = Vec::new();
    proof.serialize(&mut proof_bytes)
        .map_err(|e| anyhow!("Serialization error: {:?}", e))?;
    Ok(proof_bytes)
}

/// Deserialize a proof from bytes
pub fn deserialize_proof(proof_bytes: &[u8]) -> Result<Proof<Bn254>, anyhow::Error> {
    Proof::deserialize(proof_bytes)
        .map_err(|e| anyhow!("Deserialization error: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_std::rand::thread_rng;
    use crate::circuit_impl::PCDCircuit;
    use std::marker::PhantomData;
    
    #[test]
    fn test_simple_circuit() -> Result<(), anyhow::Error> {
        let mut rng = thread_rng();
        
        // Create a simple circuit with a single state element
        let curr_state = vec![Fr::from(42u64)];
        let circuit = PCDCircuit::<Fr> {
            bytecode: ethers::types::Bytes::from(vec![0u8]),
            prev_state: None,
            curr_state: curr_state.clone(),
            _field: PhantomData,
        };
        
        // Generate keys
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng)
            .map_err(|e| anyhow!("Setup error: {:?}", e))?;
        
        // Generate a proof
        let proof_bytes = generate_proof(circuit.clone(), &pk, &mut rng)?;
        
        // Verify the proof with the correct public inputs
        let proof = deserialize_proof(&proof_bytes)?;
        let circuit_clone = PCDCircuit::<Fr> {
            bytecode: ethers::types::Bytes::from(vec![0u8]),
            prev_state: None,
            curr_state: curr_state.clone(),
            _field: PhantomData,
        };
        let is_valid = verify_proof(circuit_clone, &proof, &vk, Some(curr_state))?;
        
        assert!(is_valid, "Proof verification should succeed");
        
        Ok(())
    }
    
    #[test]
    fn test_data_predicate() -> Result<(), anyhow::Error> {
        let mut rng = thread_rng();
        
        // Create some test data and a predicate
        let data = vec![0x01, 0x02, 0x03];
        let predicate = vec![0x04, 0x05, 0x06];
        
        // Create a circuit that checks if data satisfies the predicate
        let circuit = PCDCircuit::<Fr> {
            bytecode: ethers::types::Bytes::from(data.clone()),
            prev_state: None,
            curr_state: vec![Fr::from(data[0] as u64), Fr::from(predicate[0] as u64)],
            _field: PhantomData,
        };
        
        // Generate keys
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng)
            .map_err(|e| anyhow!("Setup error: {:?}", e))?;
        
        // Generate a proof
        let proof_bytes = generate_proof(circuit.clone(), &pk, &mut rng)?;
        
        // Create public inputs from the first byte of data and predicate
        let proof = deserialize_proof(&proof_bytes)?;
        let public_inputs = vec![Fr::from(data[0] as u64), Fr::from(predicate[0] as u64)];
        
        // Verify the proof
        let circuit_clone = PCDCircuit::<Fr> {
            bytecode: ethers::types::Bytes::from(data.clone()),
            prev_state: None,
            curr_state: vec![Fr::from(data[0] as u64), Fr::from(predicate[0] as u64)],
            _field: PhantomData,
        };
        let is_valid = verify_proof(circuit_clone, &proof, &vk, Some(public_inputs))?;
        
        assert!(is_valid, "Proof verification should succeed");
        
        Ok(())
    }
}
