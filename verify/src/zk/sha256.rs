use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSystemRef,
    SynthesisError,
    Variable,
    LinearCombination,
};

/// SHA256 circuit implementation
pub struct Sha256Circuit<F: Field> {
    cs: ConstraintSystemRef<F>,
    state: [Variable; 8],
    message_schedule: Vec<Variable>,
}

const ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl<F: Field> Sha256Circuit<F> {
    pub fn new(cs: ConstraintSystemRef<F>) -> Result<Self, SynthesisError> {
        // Initialize state with IV
        let state = [
            cs.new_input_variable(|| Ok(F::from(0x6a09e667u32 as u64)))?,
            cs.new_input_variable(|| Ok(F::from(0xbb67ae85u32 as u64)))?,
            cs.new_input_variable(|| Ok(F::from(0x3c6ef372u32 as u64)))?,
            cs.new_input_variable(|| Ok(F::from(0xa54ff53au32 as u64)))?,
            cs.new_input_variable(|| Ok(F::from(0x510e527fu32 as u64)))?,
            cs.new_input_variable(|| Ok(F::from(0x9b05688cu32 as u64)))?,
            cs.new_input_variable(|| Ok(F::from(0x1f83d9abu32 as u64)))?,
            cs.new_input_variable(|| Ok(F::from(0x5be0cd19u32 as u64)))?,
        ];

        Ok(Self {
            cs,
            state,
            message_schedule: Vec::new(),
        })
    }

    fn enforce_binary_operation(
        &self,
        a: Variable,
        b: Variable,
        result: Variable,
    ) -> Result<(), SynthesisError> {
        let lc_a = LinearCombination::from(a);
        let lc_b = LinearCombination::from(b);
        let lc_result = LinearCombination::from(result);

        // Combine a and b
        let combined = lc_a + lc_b;

        self.cs.enforce_constraint(combined, lc_result.clone(), lc_result)
    }

    pub fn process_block(&mut self, block: &[u8; 64]) -> Result<(), SynthesisError> {
        // Convert block bytes to variables
        self.message_schedule = block.iter()
            .map(|byte| {
                self.cs.new_witness_variable(|| Ok(F::from(*byte as u64)))
            })
            .collect::<Result<_, _>>()?;

        // Process each round
        for i in 0..64 {
            let k = F::from(ROUND_CONSTANTS[i] as u64);
            let k_var = self.cs.new_input_variable(|| Ok(k))?;

            // Create a new state variable for the round computation
            let new_state = self.cs.new_witness_variable(|| Ok(k))?;

            // Create linear combinations for the constraint
            let lc1 = LinearCombination::from(k_var);
            let lc2 = LinearCombination::from(self.state[i % 8]);
            let lc3 = LinearCombination::from(new_state);

            // Add the constraint: k_var * state[i % 8] = new_state
            self.cs.enforce_constraint(lc1, lc2, lc3)?;

            // Update state
            self.state[i % 8] = new_state;
        }

        Ok(())
    }

    pub fn finish(self) -> Result<[Variable; 8], SynthesisError> {
        Ok(self.state)
    }
}
