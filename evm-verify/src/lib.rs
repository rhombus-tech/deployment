use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_ec::AffineRepr;
use ark_ec::pairing::Pairing;
use rand::rngs::OsRng;

use crate::circuits::access::AccessControlCircuit;
use crate::common::DeploymentData;
use crate::bytecode::types::RuntimeAnalysis;
use crate::utils::address_to_field;

type Fr = <Bn254 as Pairing>::ScalarField;

pub mod bytecode;
pub mod circuits;
pub mod common;
pub mod ethereum;
pub mod prover;
pub mod utils;

/// Generate proving key
pub fn generate_proving_key<C>(circuit: C) -> <Groth16<Bn254> as SNARK<Fr>>::ProvingKey
where
    C: ark_relations::r1cs::ConstraintSynthesizer<Fr> + Clone,
{
    // Generate proving key
    let (pk, _) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut OsRng).unwrap();

    pk
}

/// Generate proof
pub fn generate_proof<C>(
    circuit: C,
    pk: &<Groth16<Bn254> as SNARK<Fr>>::ProvingKey,
) -> Result<ark_groth16::Proof<Bn254>, ark_relations::r1cs::SynthesisError>
where
    C: ark_relations::r1cs::ConstraintSynthesizer<Fr>,
{
    // Generate proof
    let proof = Groth16::<Bn254>::prove(pk, circuit, &mut OsRng)?;

    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keys() {
        // Create deployment data with valid owner
        let mut deployment = DeploymentData::default();
        deployment.owner = ethers::types::H160::from_low_u64_be(0x1234);

        // Create runtime analysis with matching caller
        let mut runtime = RuntimeAnalysis::default();
        runtime.caller = deployment.owner;

        // Create access control circuit
        let circuit = AccessControlCircuit::<Fr>::new(
            deployment.clone(),
            runtime.clone(),
        );

        // Generate proving key
        let pk = generate_proving_key(circuit);

        // Ensure proving key is valid
        assert!(!pk.vk.alpha_g1.is_zero());
    }

    #[test]
    fn test_generate_proof() {
        // Create deployment data with valid owner
        let mut deployment = DeploymentData::default();
        deployment.owner = ethers::types::H160::from_low_u64_be(0x1234);

        // Create runtime analysis with matching caller
        let mut runtime = RuntimeAnalysis::default();
        runtime.caller = deployment.owner;

        // Create access control circuit
        let circuit = AccessControlCircuit::<Fr>::new(
            deployment.clone(),
            runtime.clone(),
        );

        // Generate proving key
        let pk = generate_proving_key(circuit.clone());

        // Generate proof
        let proof = generate_proof(circuit, &pk).unwrap();

        // Ensure proof is valid
        assert!(!proof.a.is_zero());
    }

    #[test]
    fn test_generate_keys_circuit_specific() {
        // Create deployment data with valid owner
        let mut deployment = DeploymentData::default();
        deployment.owner = ethers::types::H160::from_low_u64_be(0x1234);

        // Create runtime analysis with matching caller
        let mut runtime = RuntimeAnalysis::default();
        runtime.caller = deployment.owner;

        // Create access control circuit
        let circuit = AccessControlCircuit::<Fr>::new(
            deployment.clone(),
            runtime.clone(),
        );

        // Generate proving and verifying keys
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut OsRng).unwrap();

        // Generate proof
        let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut OsRng).unwrap();

        // Get public inputs
        let owner_val = address_to_field::<Fr>(deployment.owner);
        let caller_val = address_to_field::<Fr>(runtime.caller);
        let public_inputs = vec![owner_val, caller_val];

        // Verify proof
        assert!(Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap());
    }
}
