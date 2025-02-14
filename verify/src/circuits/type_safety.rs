use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, 
    ConstraintSystemRef, 
    SynthesisError,
    LinearCombination,
    Variable,
};
use std::marker::PhantomData;
use crate::parser::types::ValueType;

#[derive(Clone, Debug)]
pub enum StackOp {
    Push(ValueType),
    Pop(ValueType),
    Peek(ValueType),
    BlockEntry(usize),  // Block index
    BlockExit(usize),   // Block index
}

#[derive(Clone, Debug)]
pub struct BlockContext {
    pub param_types: Vec<ValueType>,
    pub result_types: Vec<ValueType>,
    pub stack_height: usize,
}

#[derive(Debug, Clone)]
struct StackFrame {
    values: Vec<ValueType>,
}

impl StackFrame {
    fn new(values: Vec<ValueType>) -> Self {
        Self { values }
    }

    fn push(&mut self, ty: ValueType) {
        self.values.push(ty);
    }

    fn pop(&mut self) -> Option<ValueType> {
        self.values.pop()
    }

    fn can_coerce(from: &ValueType, to: &ValueType) -> bool {
        match (from, to) {
            // Allow coercion from smaller to larger integer types
            (ValueType::I32, ValueType::I64) => true,
            // No coercion between floating point types
            (ValueType::F32, ValueType::F64) => false,
            // No coercion between integer and floating point types
            (ValueType::I32, ValueType::F32) => false,
            (ValueType::I32, ValueType::F64) => false,
            (ValueType::I64, ValueType::F32) => false,
            (ValueType::I64, ValueType::F64) => false,
            // No coercion between reference types
            (ValueType::FuncRef, ValueType::ExternRef) => false,
            (ValueType::ExternRef, ValueType::FuncRef) => false,
            // Same types can always be coerced
            (a, b) if a == b => true,
            // All other combinations are invalid
            _ => false,
        }
    }
}

#[derive(Clone)]
pub struct TypeSafetyCircuit<F: Field> {
    pub stack_ops: Vec<StackOp>,
    pub block_types: Vec<BlockContext>,
    pub expected_stack: Vec<ValueType>,
    _marker: PhantomData<F>,
}

impl<F: Field> TypeSafetyCircuit<F> {
    pub fn new(
        stack_ops: Vec<StackOp>,
        block_types: Vec<BlockContext>,
        expected_stack: Vec<ValueType>,
    ) -> Self {
        Self {
            stack_ops,
            block_types,
            expected_stack,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> ConstraintSynthesizer<F> for TypeSafetyCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Initialize stack height as input variable
        let mut current_height = cs.new_input_variable(|| Ok(F::zero()))?;
        let mut stack_vars = Vec::new();

        // Helper function to convert type to field
        fn type_to_field<F: Field>(ty: ValueType) -> F {
            match ty {
                ValueType::I32 => F::from(1u32),
                ValueType::I64 => F::from(2u32),
                ValueType::F32 => F::from(3u32),
                ValueType::F64 => F::from(4u32),
                ValueType::V128 => F::from(5u32),
                ValueType::FuncRef => F::from(6u32),
                ValueType::ExternRef => F::from(7u32),
            }
        };

        // Helper function to enforce type equality
        let enforce_type_equality = |cs: &ConstraintSystemRef<F>, actual: Variable, expected: Variable| -> Result<(), SynthesisError> {
            cs.enforce_constraint(
                LinearCombination::from(actual),
                LinearCombination::from(Variable::One),
                LinearCombination::from(expected)
            )?;
            Ok(())
        };

        // Process each stack operation
        for op in self.stack_ops.iter() {
            match op {
                StackOp::Push(ty) => {
                    // Convert type to field and create variable
                    let type_val = type_to_field(*ty);
                    let type_var = cs.new_input_variable(|| Ok(type_val))?;
                    
                    // Push type onto stack
                    stack_vars.push(type_var);

                    // Update stack height
                    let new_height = cs.new_input_variable(|| Ok(F::from(stack_vars.len() as u32)))?;
                    current_height = new_height;
                }

                StackOp::Pop(expected_ty) => {
                    // Ensure stack is not empty
                    if stack_vars.is_empty() {
                        return Err(SynthesisError::Unsatisfiable);
                    }

                    // Get the actual type from stack
                    let actual_type = stack_vars.pop().unwrap();
                    let expected_val = type_to_field(*expected_ty);
                    let expected_type_var = cs.new_input_variable(|| Ok(expected_val))?;

                    // Enforce type equality
                    enforce_type_equality(&cs, actual_type, expected_type_var)?;

                    // Update stack height
                    let new_height = cs.new_input_variable(|| Ok(F::from(stack_vars.len() as u32)))?;
                    current_height = new_height;
                }

                StackOp::Peek(expected_ty) => {
                    // Ensure stack is not empty
                    if stack_vars.is_empty() {
                        return Err(SynthesisError::Unsatisfiable);
                    }

                    // Get the top type without popping
                    let top_type = *stack_vars.last().unwrap();
                    let expected_val = type_to_field(*expected_ty);
                    let expected_type_var = cs.new_input_variable(|| Ok(expected_val))?;

                    // Enforce type equality
                    enforce_type_equality(&cs, top_type, expected_type_var)?;
                }

                StackOp::BlockEntry(block_idx) => {
                    let block = &self.block_types[*block_idx];

                    // Ensure stack has enough parameters
                    if stack_vars.len() < block.param_types.len() {
                        return Err(SynthesisError::Unsatisfiable);
                    }

                    // Verify parameter types in reverse order
                    let mut temp_stack = Vec::new();
                    for expected_ty in block.param_types.iter().rev() {
                        let actual_type = stack_vars.pop().unwrap();
                        let expected_val = type_to_field(*expected_ty);
                        let expected_type_var = cs.new_input_variable(|| Ok(expected_val))?;

                        enforce_type_equality(&cs, actual_type, expected_type_var)?;
                        temp_stack.push(actual_type);
                    }

                    // Update stack height
                    let new_height = cs.new_input_variable(|| Ok(F::from(stack_vars.len() as u32)))?;
                    current_height = new_height;
                }

                StackOp::BlockExit(block_idx) => {
                    let block = &self.block_types[*block_idx];

                    // Ensure stack has enough results
                    if stack_vars.len() < block.result_types.len() {
                        return Err(SynthesisError::Unsatisfiable);
                    }

                    // Verify result types in reverse order and keep them
                    let mut temp_stack = Vec::new();
                    for expected_ty in block.result_types.iter().rev() {
                        let actual_type = stack_vars.pop().unwrap();
                        let expected_val = type_to_field(*expected_ty);
                        let expected_type_var = cs.new_input_variable(|| Ok(expected_val))?;

                        enforce_type_equality(&cs, actual_type, expected_type_var)?;
                        temp_stack.push(actual_type);
                    }

                    // Push results back onto stack in correct order
                    for var in temp_stack.into_iter().rev() {
                        stack_vars.push(var);
                    }

                    // Update stack height
                    let new_height = cs.new_input_variable(|| Ok(F::from(stack_vars.len() as u32)))?;
                    current_height = new_height;
                }
            }
        }

        // Verify final stack matches expected stack
        if stack_vars.len() != self.expected_stack.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        for (actual_var, expected_ty) in stack_vars.iter().zip(self.expected_stack.iter()) {
            let expected_val = type_to_field(*expected_ty);
            let expected_type_var = cs.new_input_variable(|| Ok(expected_val))?;

            enforce_type_equality(&cs, *actual_var, expected_type_var)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_push_pop() {
        let mut ops = Vec::new();
        ops.push(StackOp::Push(ValueType::I32));
        ops.push(StackOp::Pop(ValueType::I32));

        let circuit = TypeSafetyCircuit {
            stack_ops: ops,
            block_types: vec![],
            expected_stack: vec![],
            _marker: PhantomData,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_type_mismatch() {
        let mut ops = Vec::new();
        ops.push(StackOp::Push(ValueType::I32));
        ops.push(StackOp::Pop(ValueType::I64)); // Type mismatch

        let circuit = TypeSafetyCircuit {
            stack_ops: ops,
            block_types: vec![],
            expected_stack: vec![],
            _marker: PhantomData,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        let result = circuit.generate_constraints(cs.clone());
        assert!(result.is_ok());
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_invalid_pop() {
        let mut ops = Vec::new();
        ops.push(StackOp::Pop(ValueType::I32)); // Pop from empty stack

        let circuit = TypeSafetyCircuit {
            stack_ops: ops,
            block_types: vec![],
            expected_stack: vec![],
            _marker: PhantomData,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs.clone()).is_err());
    }

    #[test]
    fn test_block_operations() {
        let mut ops = Vec::new();
        ops.push(StackOp::Push(ValueType::I32));
        ops.push(StackOp::Push(ValueType::I64));
        
        let block = BlockContext {
            param_types: vec![ValueType::I32, ValueType::I64],
            result_types: vec![ValueType::I32],
            stack_height: 0,
        };
        
        ops.push(StackOp::BlockEntry(0));
        ops.push(StackOp::Push(ValueType::I32));
        ops.push(StackOp::BlockExit(0));

        let circuit = TypeSafetyCircuit {
            stack_ops: ops,
            block_types: vec![block],
            expected_stack: vec![ValueType::I32],
            _marker: PhantomData,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_peek() {
        let mut ops = Vec::new();
        ops.push(StackOp::Push(ValueType::I32));
        ops.push(StackOp::Peek(ValueType::I32));

        let circuit = TypeSafetyCircuit {
            stack_ops: ops,
            block_types: vec![],
            expected_stack: vec![ValueType::I32],
            _marker: PhantomData,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(cs.is_satisfied().unwrap());
    }
}
