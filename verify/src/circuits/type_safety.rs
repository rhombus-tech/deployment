use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, 
    ConstraintSystemRef, 
    SynthesisError,
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
    fn new() -> Self {
        Self { values: Vec::new() }
    }

    fn push(&mut self, ty: ValueType) {
        self.values.push(ty);
    }

    fn pop(&mut self) -> Option<ValueType> {
        self.values.pop()
    }

    fn can_coerce(from: &ValueType, to: &ValueType) -> bool {
        match (from, to) {
            // Identity coercions
            (a, b) if a == b => true,
            // Integer coercions
            (ValueType::I32, ValueType::I64) => true,
            // Float coercions
            (ValueType::F32, ValueType::F64) => true,
            // Integer to float coercions
            (ValueType::I32, ValueType::F32) => true,
            (ValueType::I32, ValueType::F64) => true,
            (ValueType::I64, ValueType::F64) => true,
            // Reference type coercions
            (ValueType::FuncRef, ValueType::ExternRef) => true,
            // No other coercions are valid
            _ => false,
        }
    }

    // Stricter coercion rules for final stack validation
    fn can_coerce_final(from: &ValueType, to: &ValueType) -> bool {
        from == to
    }

    // Stricter coercion rules for block parameters
    fn can_coerce_block_param(from: &ValueType, to: &ValueType) -> bool {
        from == to
    }
}

#[derive(Clone)]
pub struct TypeSafetyCircuit<F: Field> {
    stack_ops: Vec<StackOp>,
    block_types: Vec<BlockContext>,
    expected_stack: Vec<ValueType>,
    _phantom: PhantomData<F>,
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
            _phantom: PhantomData,
        }
    }

    fn validate_numeric_op(
        op1_type: &ValueType,
        op2_type: &ValueType,
        result_type: &ValueType,
        is_comparison: bool,
    ) -> bool {
        match (op1_type, op2_type, result_type) {
            // Integer operations and comparisons
            (ValueType::I32, ValueType::I32, ValueType::I32) => true,
            (ValueType::I64, ValueType::I64, ValueType::I64) => !is_comparison,
            (ValueType::I64, ValueType::I64, ValueType::I32) => is_comparison,
            
            // Float operations and comparisons
            (ValueType::F32, ValueType::F32, ValueType::F32) => !is_comparison,
            (ValueType::F64, ValueType::F64, ValueType::F64) => !is_comparison,
            (ValueType::F32, ValueType::F32, ValueType::I32) => is_comparison,
            (ValueType::F64, ValueType::F64, ValueType::I32) => is_comparison,
            
            // No other numeric operations are valid
            _ => false,
        }
    }

    fn validate_memory_access(
        value_type: &ValueType,
        access_type: &ValueType,
        is_store: bool,
    ) -> bool {
        match (value_type, access_type) {
            // Direct matches
            (a, b) if a == b => true,
            
            // Integer loads can be extended
            (ValueType::I32, ValueType::I64) if !is_store => true,
            
            // Float loads must match exactly
            (ValueType::F32, ValueType::F32) => true,
            (ValueType::F64, ValueType::F64) => true,
            
            // Reference types cannot be stored in linear memory
            (ValueType::FuncRef, _) => false,
            (ValueType::ExternRef, _) => false,
            
            // No other memory access patterns are valid
            _ => false,
        }
    }
}

impl<F: Field> ConstraintSynthesizer<F> for TypeSafetyCircuit<F> {
    fn generate_constraints(
        self,
        _cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        let mut stack = StackFrame::new();
        let mut block_contexts: Vec<(usize, BlockContext)> = Vec::new();
        
        // Process each stack operation
        for op in self.stack_ops.iter() {
            println!("Processing op: {:?}", op);
            println!("Current stack: {:?}", stack.values);
            
            match op {
                StackOp::Push(ty) => {
                    stack.push(*ty);
                }
                
                StackOp::Pop(expected_ty) => {
                    match stack.pop() {
                        Some(actual_ty) if StackFrame::can_coerce(&actual_ty, &expected_ty) => (),
                        _ => return Err(SynthesisError::Unsatisfiable),
                    }
                }
                
                StackOp::Peek(expected_ty) => {
                    if stack.values.is_empty() {
                        return Err(SynthesisError::Unsatisfiable);
                    }
                    
                    let actual_ty = *stack.values.last().unwrap();
                    if !StackFrame::can_coerce(&actual_ty, &expected_ty) {
                        println!("Peek failed: actual={:?}, expected={:?}", actual_ty, expected_ty);
                        return Err(SynthesisError::Unsatisfiable);
                    }
                }
                
                StackOp::BlockEntry(block_idx) => {
                    let context = &self.block_types[*block_idx];
                    println!("Entering block {}: params={:?}, results={:?}", block_idx, context.param_types, context.result_types);
                    
                    // Check if we have enough values for parameters
                    if stack.values.len() < context.param_types.len() {
                        return Err(SynthesisError::Unsatisfiable);
                    }
                    
                    // Get parameter values from stack
                    let stack_len = stack.values.len();
                    let param_start = stack_len - context.param_types.len();
                    let param_values = &stack.values[param_start..];
                    println!("Param values: {:?}", param_values);
                    
                    // Validate parameter types in order (bottom of stack to top)
                    for (i, (actual_ty, expected_ty)) in param_values.iter().zip(context.param_types.iter()).enumerate() {
                        println!("Checking param {}: actual={:?}, expected={:?}", i, actual_ty, expected_ty);
                        if !StackFrame::can_coerce_block_param(actual_ty, expected_ty) {
                            println!("Parameter validation failed");
                            return Err(SynthesisError::Unsatisfiable);
                        }
                    }
                    
                    // Remove only the parameter values
                    let non_param_values: Vec<_> = stack.values[..param_start].to_vec();
                    stack.values = non_param_values;
                    
                    block_contexts.push((*block_idx, context.clone()));
                }
                
                StackOp::BlockExit(block_idx) => {
                    let (entry_idx, context) = block_contexts.pop().ok_or(SynthesisError::Unsatisfiable)?;
                    println!("Exiting block {}: params={:?}, results={:?}", block_idx, context.param_types, context.result_types);
                    
                    // Verify block index matches
                    if *block_idx != entry_idx {
                        return Err(SynthesisError::Unsatisfiable);
                    }
                    
                    // Check if we have enough values for results
                    if stack.values.len() < context.result_types.len() {
                        return Err(SynthesisError::Unsatisfiable);
                    }
                    
                    // Get result values from stack
                    let stack_len = stack.values.len();
                    let result_start = stack_len - context.result_types.len();
                    let result_values = &stack.values[result_start..];
                    println!("Result values: {:?}", result_values);
                    
                    // Validate result types in order (bottom of stack to top)
                    for (i, (actual_ty, expected_ty)) in result_values.iter().zip(context.result_types.iter()).enumerate() {
                        println!("Checking result: actual={:?}, expected={:?}", actual_ty, expected_ty);
                        if !StackFrame::can_coerce(actual_ty, expected_ty) {
                            println!("Result validation failed");
                            return Err(SynthesisError::Unsatisfiable);
                        }
                    }
                    
                    // Remove old results and push new ones with coerced types
                    stack.values.truncate(result_start);
                    for ty in context.result_types.iter() {
                        stack.push(*ty);
                    }
                }
            }
            
            println!("Stack after op: {:?}", stack.values);
        }
        
        // Verify final stack matches expected
        if stack.values.len() != self.expected_stack.len() {
            println!("Final stack length mismatch: actual={}, expected={}", stack.values.len(), self.expected_stack.len());
            return Err(SynthesisError::Unsatisfiable);
        }
        
        for (actual_ty, expected_ty) in stack.values.iter().zip(self.expected_stack.iter()) {
            println!("Checking final stack value: actual={:?}, expected={:?}", actual_ty, expected_ty);
            if !StackFrame::can_coerce_final(actual_ty, expected_ty) {
                println!("Final stack type mismatch");
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
    fn test_type_coercion() {
        // Test valid coercions
        assert!(StackFrame::can_coerce(&ValueType::I32, &ValueType::I32));
        assert!(StackFrame::can_coerce(&ValueType::I32, &ValueType::I64));
        assert!(StackFrame::can_coerce(&ValueType::F32, &ValueType::F64));
        assert!(StackFrame::can_coerce(&ValueType::FuncRef, &ValueType::ExternRef));
        assert!(StackFrame::can_coerce(&ValueType::I32, &ValueType::F32));
        assert!(StackFrame::can_coerce(&ValueType::I32, &ValueType::F64));
        assert!(StackFrame::can_coerce(&ValueType::I64, &ValueType::F64));
        
        // Test invalid coercions
        assert!(!StackFrame::can_coerce(&ValueType::I64, &ValueType::I32));
        assert!(!StackFrame::can_coerce(&ValueType::F64, &ValueType::F32));
        assert!(!StackFrame::can_coerce(&ValueType::ExternRef, &ValueType::FuncRef));
        assert!(!StackFrame::can_coerce(&ValueType::F32, &ValueType::I32));
        assert!(!StackFrame::can_coerce(&ValueType::F64, &ValueType::I32));
        assert!(!StackFrame::can_coerce(&ValueType::F64, &ValueType::I64));
    }

    #[test]
    fn test_nested_blocks() {
        let circuit = TypeSafetyCircuit::<Fr>::new(
            vec![
                // Outer block parameters
                StackOp::Push(ValueType::I32),
                StackOp::Push(ValueType::I64),
                StackOp::BlockEntry(0),
                
                // Inner block
                StackOp::Push(ValueType::F32),
                StackOp::BlockEntry(1),
                StackOp::Push(ValueType::F64),
                StackOp::BlockExit(1),
                
                // Finish outer block
                StackOp::BlockExit(0),
            ],
            vec![
                // Outer block type
                BlockContext {
                    param_types: vec![ValueType::I32, ValueType::I64],
                    result_types: vec![ValueType::F64],
                    stack_height: 2,
                },
                // Inner block type
                BlockContext {
                    param_types: vec![ValueType::F32],
                    result_types: vec![ValueType::F64],
                    stack_height: 1,
                },
            ],
            vec![ValueType::F64],
        );
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs).is_ok());
    }

    #[test]
    fn test_invalid_block_exit() {
        let circuit = TypeSafetyCircuit::<Fr>::new(
            vec![
                StackOp::Push(ValueType::I32),
                // Try to enter block expecting F32
                StackOp::BlockEntry(0),
                StackOp::Push(ValueType::I64),
                // Try to exit block 1 when we're in block 0
                StackOp::BlockExit(1),
            ],
            vec![BlockContext {
                param_types: vec![ValueType::I32],
                result_types: vec![ValueType::I64],
                stack_height: 1,
            }],
            vec![ValueType::I64],
        );
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs).is_err());
    }

    #[test]
    fn test_stack_underflow() {
        let circuit = TypeSafetyCircuit::<Fr>::new(
            vec![
                StackOp::Push(ValueType::I32),
                StackOp::Pop(ValueType::I32),
                // Try to pop from empty stack
                StackOp::Pop(ValueType::I32),
            ],
            vec![],
            vec![],
        );
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs).is_err());
    }

    #[test]
    fn test_invalid_final_stack() {
        let circuit = TypeSafetyCircuit::<Fr>::new(
            vec![
                StackOp::Push(ValueType::I32),
                StackOp::Push(ValueType::I64),
            ],
            vec![],
            // Expect different types than what's on the stack
            vec![ValueType::F32, ValueType::F64],
        );
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs).is_err());
    }

    #[test]
    fn test_complex_type_sequence() {
        let circuit = TypeSafetyCircuit::<Fr>::new(
            vec![
                // Push some values
                StackOp::Push(ValueType::I32),
                StackOp::Push(ValueType::F32),
                
                // Enter block that takes F32 and returns I64
                StackOp::BlockEntry(0),
                StackOp::Push(ValueType::I64),
                StackOp::BlockExit(0),
                
                // Peek at the I64
                StackOp::Peek(ValueType::I64),
                
                // Swap I32 and I64 for block 1
                StackOp::Pop(ValueType::I64),
                StackOp::Pop(ValueType::I32),
                StackOp::Push(ValueType::I32),
                StackOp::Push(ValueType::I64),
                
                // Enter another block that takes I32 and I64
                StackOp::BlockEntry(1),
                StackOp::Push(ValueType::F64),
                StackOp::BlockExit(1),
            ],
            vec![
                BlockContext {
                    param_types: vec![ValueType::F32],
                    result_types: vec![ValueType::I64],
                    stack_height: 1,
                },
                BlockContext {
                    param_types: vec![ValueType::I32, ValueType::I64],
                    result_types: vec![ValueType::F64],
                    stack_height: 2,
                },
            ],
            vec![ValueType::F64],
        );
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs).is_ok());
    }

    #[test]
    fn test_invalid_block_params() {
        let circuit = TypeSafetyCircuit::<Fr>::new(
            vec![
                StackOp::Push(ValueType::I32),
                // Try to enter block expecting F32
                StackOp::BlockEntry(0),
            ],
            vec![BlockContext {
                param_types: vec![ValueType::F32],
                result_types: vec![ValueType::I64],
                stack_height: 1,
            }],
            vec![ValueType::I64],
        );
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs).is_err());
    }

    #[test]
    fn test_invalid_block_results() {
        let circuit = TypeSafetyCircuit::<Fr>::new(
            vec![
                StackOp::Push(ValueType::I32),
                StackOp::BlockEntry(0),
                // Push wrong type for block result
                StackOp::Push(ValueType::F32),
                StackOp::BlockExit(0),
            ],
            vec![BlockContext {
                param_types: vec![ValueType::I32],
                result_types: vec![ValueType::I64],
                stack_height: 1,
            }],
            vec![ValueType::I64],
        );
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs).is_err());
    }
}
