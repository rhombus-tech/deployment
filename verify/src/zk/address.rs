use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer,
    ConstraintSystemRef,
    SynthesisError,
    Variable,
    LinearCombination,
};
use sha2::{Sha256, Digest};
use std::marker::PhantomData;

pub struct AddressPrivacyCircuit<F: Field> {
    /// The deployer's address (private input)
    address: Vec<u8>,
    /// Hash of the address (public input)
    address_hash: Vec<u8>,
    /// Phantom data for the field type
    _phantom: PhantomData<F>,
}

impl<F: Field> Default for AddressPrivacyCircuit<F> {
    fn default() -> Self {
        // Use a dummy address for circuit setup
        let address = vec![0u8; 32];
        Self::new(address)
    }
}

impl<F: Field> AddressPrivacyCircuit<F> {
    pub fn new(address: Vec<u8>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&address);
        let address_hash = hasher.finalize().to_vec();
        
        Self {
            address,
            address_hash,
            _phantom: PhantomData,
        }
    }
}

impl<F: Field> ConstraintSynthesizer<F> for AddressPrivacyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Convert address bytes to field elements
        let address_vars: Vec<Variable> = self.address
            .iter()
            .map(|byte| cs.new_witness_variable(|| Ok(F::from(*byte as u64))))
            .collect::<Result<_, _>>()?;

        // Convert hash bytes to field elements (public)
        let hash_vars: Vec<Variable> = self.address_hash
            .iter()
            .map(|byte| cs.new_input_variable(|| Ok(F::from(*byte as u64))))
            .collect::<Result<_, _>>()?;

        // Create a variable for constant one
        let one = cs.new_input_variable(|| Ok(F::one()))?;

        // Enforce equality using cs.enforce_constraint
        for (a, h) in address_vars.iter().zip(hash_vars.iter()) {
            let a_lc = LinearCombination::from(*a);
            let h_lc = LinearCombination::from(*h);
            let one_lc = LinearCombination::from(one);
            
            cs.enforce_constraint(
                a_lc,
                one_lc,
                h_lc,
            )?;
        }

        Ok(())
    }
}
