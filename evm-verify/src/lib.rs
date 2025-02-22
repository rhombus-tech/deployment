use ark_ff::PrimeField;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_groth16::{Groth16, ProvingKey};
use ark_snark::SNARK;
use ark_bn254::{Bn254, Fr};
use ark_ec::AffineRepr;
use rand::rngs::OsRng;

pub mod bytecode;
pub mod circuits;
pub mod common;
pub mod ethereum;
pub mod prover;
pub mod utils;

/// Generate proving key
pub fn generate_proving_key<C>(circuit: C) -> ProvingKey<Bn254> 
where 
    C: ConstraintSynthesizer<Fr> + Clone,
{
    // Generate proving key
    let (pk, _) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut OsRng).unwrap();

    pk
}

/// Generate proof
pub fn generate_proof<C>(
    circuit: C,
    pk: &ProvingKey<Bn254>,
) -> Result<ark_groth16::Proof<Bn254>, ark_relations::r1cs::SynthesisError>
where
    C: ConstraintSynthesizer<Fr>,
{
    // Generate proof
    let proof = Groth16::<Bn254>::prove(pk, circuit, &mut OsRng)?;

    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::{H160, H256};
    use crate::circuits::constructor::ConstructorCircuit;
    use crate::circuits::access::AccessControlCircuit;
    use crate::common::DeploymentData;
    use crate::bytecode::types::{RuntimeAnalysis, StateTransition};

    #[test]
    fn test_generate_keys() {
        // Create dummy circuit
        let circuit = ConstructorCircuit::<Fr>::new(
            DeploymentData::default(),
            RuntimeAnalysis::default(),
        );

        // Generate proving key
        let _pk = generate_proving_key(circuit);
    }

    #[test]
    fn test_generate_proof() {
        // Create deployment data with valid owner
        let mut deployment = DeploymentData::default();
        deployment.owner = H160::from_low_u64_be(0x1234);

        // Create runtime analysis with valid data
        let mut runtime = RuntimeAnalysis::default();
        runtime.caller = deployment.owner;
        runtime.state_transitions.push(StateTransition {
            slot: H256::random(),
            value: Default::default(),
            write: true,
            pc: 0,
        });

        // Create circuit
        let circuit = ConstructorCircuit::<Fr>::new(
            deployment,
            runtime,
        );

        // Generate proving key
        let pk = generate_proving_key(circuit.clone());

        // Generate proof
        let _proof = generate_proof(circuit, &pk).unwrap();
    }

    #[test]
    fn test_generate_keys_circuit_specific() {
        // Create deployment data
        let deployment = DeploymentData::default();

        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();

        // Create access control circuit
        let circuit = AccessControlCircuit::<Fr>::new(
            deployment,
            runtime,
        );

        // Generate proving and verifying keys
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut OsRng).unwrap();

        // Check proving key is valid
        assert!(!pk.beta_g1.is_zero());

        // Check verifying key is valid
        assert!(!vk.alpha_g1.is_zero());
    }

    #[test]
    fn test_generate_proof_circuit_specific() {
        // Create deployment data with valid owner
        let mut deployment = DeploymentData::default();
        deployment.owner = H160::from_low_u64_be(0x1234);

        // Create runtime analysis with matching caller
        let mut runtime = RuntimeAnalysis::default();
        runtime.caller = deployment.owner;

        // Create access control circuit
        let circuit = AccessControlCircuit::<Fr>::new(
            deployment,
            runtime,
        );

        // Generate proving and verifying keys
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut OsRng).unwrap();

        // Generate proof
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut OsRng).unwrap();

        // Verify proof
        assert!(Groth16::<Bn254>::verify(&vk, &[], &proof).unwrap());
    }
}
