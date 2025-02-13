use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
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
        _cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        let mut stack_frames = vec![StackFrame::new(vec![])];

        for op in self.stack_ops.iter() {
            println!("Processing stack op: {:?}", op);

            match op {
                StackOp::Push(ty) => {
                    let current_frame = stack_frames.last_mut().unwrap();
                    println!("Verifying push of {:?}", ty);
                    current_frame.push(*ty);
                    println!("Stack after push: {:?}", current_frame.values);
                }
                StackOp::Pop(ty) => {
                    let current_frame = stack_frames.last_mut().unwrap();
                    println!("Verifying pop of {:?}", ty);
                    match current_frame.pop() {
                        Some(actual_ty) => {
                            if !StackFrame::can_coerce(&actual_ty, &ty) {
                                println!("Error: Type mismatch on pop. Expected {:?}, got {:?}", ty, actual_ty);
                                return Err(SynthesisError::Unsatisfiable);
                            }
                            println!("Stack after pop: {:?}", current_frame.values);
                        }
                        None => {
                            println!("Error: Cannot pop from empty stack");
                            return Err(SynthesisError::Unsatisfiable);
                        }
                    }
                }
                StackOp::Peek(ty) => {
                    let current_frame = stack_frames.last_mut().unwrap();
                    println!("Verifying peek of {:?}", ty);
                    if current_frame.values.is_empty() {
                        println!("Error: Cannot peek empty stack");
                        return Err(SynthesisError::Unsatisfiable);
                    }
                    let actual_ty = current_frame.values.last().unwrap();
                    if !StackFrame::can_coerce(actual_ty, &ty) {
                        println!("Error: Type mismatch on peek. Expected {:?}, got {:?}", ty, actual_ty);
                        return Err(SynthesisError::Unsatisfiable);
                    }
                }
                StackOp::BlockEntry(block_idx) => {
                    println!("Entering block {}", block_idx);
                    let block = &self.block_types[*block_idx];
                    let current_frame = stack_frames.last_mut().unwrap();
                    
                    if current_frame.values.len() < block.param_types.len() {
                        println!("Error: Not enough values for block parameters");
                        return Err(SynthesisError::Unsatisfiable);
                    }
                    
                    let param_count = block.param_types.len();
                    let param_start = current_frame.values.len() - param_count;
                    let param_values: Vec<ValueType> = current_frame.values.drain(param_start..).collect();
                    
                    for (param_ty, expected_ty) in param_values.iter().zip(block.param_types.iter()) {
                        if !StackFrame::can_coerce(param_ty, expected_ty) {
                            println!("Error: Type mismatch on block entry. Expected {:?}, got {:?}", expected_ty, param_ty);
                            return Err(SynthesisError::Unsatisfiable);
                        }
                    }
                    
                    let new_frame = StackFrame::new(param_values);
                    stack_frames.push(new_frame);
                    
                    println!("Stack after block entry: {:?}", stack_frames.last().unwrap().values);
                }
                StackOp::BlockExit(block_idx) => {
                    println!("Exiting block {}", block_idx);
                    let block = &self.block_types[*block_idx];
                    
                    if stack_frames.len() <= 1 {
                        println!("Error: No block frame to exit from");
                        return Err(SynthesisError::Unsatisfiable);
                    }
                    
                    let block_frame = stack_frames.last().unwrap();
                    
                    if block_frame.values.len() < block.result_types.len() {
                        println!("Error: Not enough values for block results");
                        return Err(SynthesisError::Unsatisfiable);
                    }
                    
                    let result_count = block.result_types.len();
                    let result_start = block_frame.values.len() - result_count;
                    
                    // Check that all result values exactly match their expected types
                    for i in 0..result_count {
                        let result_ty = &block_frame.values[result_start + i];
                        let expected_ty = &block.result_types[i];
                        if result_ty != expected_ty {
                            println!("Error: Type mismatch on block exit. Expected {:?}, got {:?}", expected_ty, result_ty);
                            return Err(SynthesisError::Unsatisfiable);
                        }
                    }
                    
                    // Pop the block frame and get its values
                    let mut block_frame = stack_frames.pop().unwrap();
                    let result_values = block_frame.values.split_off(result_start);
                    
                    // Push the result values onto the parent frame
                    let parent_frame = stack_frames.last_mut().unwrap();
                    for value in result_values {
                        parent_frame.push(value);
                    }
                    
                    println!("Stack after block exit: {:?}", parent_frame.values);
                }
            }
        }

        let final_frame = stack_frames.last().unwrap();
        println!("Final stack state: {:?}", final_frame.values);
        println!("Expected stack state: {:?}", self.expected_stack);

        if final_frame.values.len() != self.expected_stack.len() {
            println!("Stack state mismatch: length differs");
            return Err(SynthesisError::Unsatisfiable);
        }

        for (actual, expected) in final_frame.values.iter().zip(self.expected_stack.iter()) {
            if !StackFrame::can_coerce(actual, expected) {
                println!("Stack state mismatch: type coercion failed");
                return Err(SynthesisError::Unsatisfiable);
            }
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
    fn test_basic_stack_operations() -> Result<(), SynthesisError> {
        let stack_ops = vec![
            StackOp::Push(ValueType::I32),
            StackOp::Push(ValueType::I64),
            StackOp::Pop(ValueType::I64),
        ];

        let block_types = vec![];
        let expected_stack = vec![ValueType::I32];

        let circuit = TypeSafetyCircuit::<Fr>::new(
            stack_ops,
            block_types,
            expected_stack,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone())?;
        assert!(cs.is_satisfied()?);
        Ok(())
    }

    #[test]
    fn test_mixed_type_operations() -> Result<(), SynthesisError> {
        let stack_ops = vec![
            StackOp::Push(ValueType::I32),
            StackOp::Push(ValueType::F32),
            StackOp::Push(ValueType::I64),
            StackOp::Pop(ValueType::I64),
            StackOp::Pop(ValueType::F32),
        ];

        let block_types = vec![];
        let expected_stack = vec![ValueType::I32];

        let circuit = TypeSafetyCircuit::<Fr>::new(
            stack_ops.clone(),
            block_types.clone(),
            expected_stack.clone(),
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone())?;
        assert!(cs.is_satisfied()?);
        Ok(())
    }

    #[test]
    fn test_peek_operations() -> Result<(), SynthesisError> {
        let stack_ops = vec![
            StackOp::Push(ValueType::I32),
            StackOp::Push(ValueType::I64),
            StackOp::Peek(ValueType::I64),
        ];

        let block_types = vec![];
        let expected_stack = vec![ValueType::I32, ValueType::I64];

        let circuit = TypeSafetyCircuit::<Fr>::new(
            stack_ops,
            block_types,
            expected_stack,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone())?;
        assert!(cs.is_satisfied()?);
        Ok(())
    }

    #[test]
    fn test_funcref_and_externref() -> Result<(), SynthesisError> {
        let stack_ops = vec![
            StackOp::Push(ValueType::I32),
            StackOp::Push(ValueType::FuncRef),
            StackOp::Push(ValueType::ExternRef),
            StackOp::Pop(ValueType::ExternRef),
            StackOp::Pop(ValueType::FuncRef),
        ];

        let block_types = vec![];
        let expected_stack = vec![ValueType::I32];

        let circuit = TypeSafetyCircuit::<Fr>::new(
            stack_ops,
            block_types,
            expected_stack,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone())?;
        assert!(cs.is_satisfied()?);
        Ok(())
    }

    #[test]
    fn test_empty_stack_operations() -> Result<(), SynthesisError> {
        // Test popping from empty stack
        let stack_ops = vec![
            StackOp::Pop(ValueType::I32),
        ];

        let block_types = vec![];
        let expected_stack = vec![];

        let circuit = TypeSafetyCircuit::<Fr>::new(
            stack_ops.clone(),
            block_types.clone(),
            expected_stack.clone(),
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs.clone()).is_err());

        // Test peeking empty stack
        let stack_ops = vec![
            StackOp::Peek(ValueType::I32),
        ];

        let circuit = TypeSafetyCircuit::<Fr>::new(
            stack_ops,
            block_types,
            expected_stack,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs.clone()).is_err());
        Ok(())
    }

    #[test]
    fn test_invalid_type_coercion() -> Result<(), SynthesisError> {
        // Test invalid coercion from I64 to I32
        let stack_ops = vec![
            StackOp::Push(ValueType::I64),
            StackOp::Pop(ValueType::I32),
        ];

        let block_types = vec![];
        let expected_stack = vec![];

        let circuit = TypeSafetyCircuit::<Fr>::new(
            stack_ops.clone(),
            block_types.clone(),
            expected_stack.clone(),
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs.clone()).is_err());

        // Test invalid coercion from F32 to I32
        let stack_ops = vec![
            StackOp::Push(ValueType::F32),
            StackOp::Pop(ValueType::I32),
        ];

        let circuit = TypeSafetyCircuit::<Fr>::new(
            stack_ops,
            block_types,
            expected_stack,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs.clone()).is_err());
        Ok(())
    }

    #[test]
    fn test_block_validation() -> Result<(), SynthesisError> {
        let block_context = BlockContext {
            param_types: vec![ValueType::I32],
            result_types: vec![ValueType::I64],
            stack_height: 1,
        };

        println!("Block params: {:?}", block_context.param_types);
        println!("Block results: {:?}", block_context.result_types);

        let stack_ops = vec![
            StackOp::Push(ValueType::I32),
            StackOp::BlockEntry(0),
            StackOp::Pop(ValueType::I32),
            StackOp::Push(ValueType::I64),
            StackOp::BlockExit(0),
        ];

        let block_types = vec![block_context];

        let circuit = TypeSafetyCircuit::<Fr>::new(
            stack_ops,
            block_types,
            vec![ValueType::I64],
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone())?;
        assert!(cs.is_satisfied()?);
        Ok(())
    }

    #[test]
    fn test_invalid_block_validation() -> Result<(), SynthesisError> {
        let block_context = BlockContext {
            param_types: vec![ValueType::I32, ValueType::I32],
            result_types: vec![ValueType::I64],
            stack_height: 2,
        };

        let stack_ops = vec![
            StackOp::Push(ValueType::I32),
            StackOp::Push(ValueType::I64), // Wrong type
            StackOp::BlockEntry(0),
        ];

        let block_types = vec![block_context];
        let expected_stack = vec![ValueType::I64];

        let circuit = TypeSafetyCircuit::<Fr>::new(
            stack_ops.clone(),
            block_types.clone(),
            expected_stack.clone(),
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs.clone()).is_err());
        Ok(())
    }

    #[test]
    fn test_invalid_block_exit() -> Result<(), SynthesisError> {
        let block_context = BlockContext {
            param_types: vec![ValueType::I32],
            result_types: vec![ValueType::I64],
            stack_height: 1,
        };

        let stack_ops = vec![
            StackOp::Push(ValueType::I32),  // Push parameter
            StackOp::BlockEntry(0),         // Enter block
            StackOp::Pop(ValueType::I32),   // Pop parameter
            StackOp::Push(ValueType::I32),  // Push wrong type (I32 instead of I64)
            StackOp::BlockExit(0),          // Try to exit with wrong type
        ];

        let block_types = vec![block_context];
        let expected_stack = vec![ValueType::I64];

        let circuit = TypeSafetyCircuit::<Fr>::new(
            stack_ops,
            block_types,
            expected_stack,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        let result = circuit.generate_constraints(cs.clone());
        assert!(result.is_err(), "Expected error due to type mismatch on block exit");
        Ok(())
    }
}
