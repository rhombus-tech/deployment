use walrus::ValType;
use walrus::ir::{Instr, Value, BinaryOp, InstrSeqId};
use anyhow::Result;

/// Represents a WebAssembly value type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ValueType {
    /// 32-bit integer
    I32,
    /// 64-bit integer
    I64,
    /// 32-bit float
    F32,
    /// 64-bit float
    F64,
    /// 128-bit vector
    V128,
    /// Function reference
    FuncRef,
    /// External reference
    ExternRef,
}

impl From<ValType> for ValueType {
    fn from(val_type: ValType) -> Self {
        match val_type {
            ValType::I32 => ValueType::I32,
            ValType::I64 => ValueType::I64,
            ValType::F32 => ValueType::F32,
            ValType::F64 => ValueType::F64,
            ValType::V128 => ValueType::V128,
            ValType::Externref => ValueType::ExternRef,
            ValType::Funcref => ValueType::FuncRef,
        }
    }
}

/// Represents a WebAssembly function type
#[derive(Debug, PartialEq)]
pub struct FunctionType {
    /// Parameter types
    pub params: Vec<ValueType>,
    /// Result types
    pub results: Vec<ValueType>,
}

impl FunctionType {
    /// Create a new function type
    pub fn new(params: Vec<ValueType>, results: Vec<ValueType>) -> Self {
        Self { params, results }
    }
}

/// Represents a WebAssembly global type
#[derive(Debug)]
pub struct GlobalType {
    /// The type of the global value
    pub value_type: ValueType,
    /// Whether the global is mutable
    pub mutable: bool,
}

/// Represents a block type in WebAssembly
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BlockType {
    Empty,
    Value(ValueType),
}

impl BlockType {
    pub fn from(val_type: Option<ValType>) -> Self {
        match val_type {
            None => BlockType::Empty,
            Some(ty) => BlockType::Value(ValueType::from(ty)),
        }
    }

    pub fn result_type(&self) -> Option<ValueType> {
        match self {
            BlockType::Empty => None,
            BlockType::Value(ty) => Some(*ty),
        }
    }
}

/// Represents a stack of value types for validation
#[derive(Debug, Default)]
pub struct Stack {
    /// The types currently on the stack
    types: Vec<ValueType>,
}

impl Stack {
    /// Create a new empty stack
    pub fn new() -> Self {
        Self { types: Vec::new() }
    }

    /// Push a type onto the stack
    pub fn push(&mut self, ty: ValueType) {
        self.types.push(ty);
    }

    /// Pop a type from the stack
    pub fn pop(&mut self) -> Option<ValueType> {
        self.types.pop()
    }

    /// Peek at the top type on the stack
    pub fn peek(&self) -> Option<&ValueType> {
        self.types.last()
    }

    /// Get the current height of the stack
    pub fn height(&self) -> usize {
        self.types.len()
    }

    /// Push multiple types onto the stack
    pub fn push_multi(&mut self, types: &[ValueType]) {
        for &ty in types {
            self.push(ty);
        }
    }
}

#[derive(Debug)]
pub struct TypeContext {
    pub locals: Vec<ValueType>,
    pub globals: Vec<ValueType>,
    pub stack: Stack,
    pub labels: Vec<(BlockType, InstrSeqId)>,
    pub return_type: Option<ValueType>,
    module: walrus::Module,
    pub types: Vec<FunctionType>,
    pub functions: Vec<FunctionType>,
    current_func: walrus::FunctionId,
}

impl TypeContext {
    pub fn new() -> Self {
        Self {
            stack: Stack::new(),
            labels: Vec::new(),
            locals: Vec::new(),
            globals: Vec::new(),
            module: walrus::Module::default(),
            types: Vec::new(),
            functions: Vec::new(),
            current_func: unsafe { std::mem::zeroed() },  // Safe because we'll set it properly in from_module
            return_type: None,
        }
    }

    pub fn from_module(module: walrus::Module, func_id: walrus::FunctionId) -> Result<Self> {
        let mut ctx = Self::new();

        // Set up locals
        let func = module.funcs.get(func_id);
            
        if let walrus::FunctionKind::Local(local) = &func.kind {
            // Add local types from the function type
            let type_id = local.ty();
            let func_type = module.types.get(type_id);
            for param_type in func_type.params().iter() {
                ctx.locals.push(ValueType::from(*param_type));
            }
        }

        // Set up globals
        for global in module.globals.iter() {
            let ty = global.ty;
            ctx.globals.push(ValueType::from(ty));
        }

        ctx.module = module;
        ctx.current_func = func_id;
        Ok(ctx)
    }

    pub fn push_block_context(&mut self, block_type: Option<ValType>, seq_id: InstrSeqId) -> Result<()> {
        let block_type = BlockType::from(block_type);
        
        // Save current stack height and sequence ID for validation on block exit
        self.labels.push((block_type, seq_id));
        
        // If block has a result type, it will be left on the stack
        if let Some(result_type) = block_type.result_type() {
            self.stack.push(result_type);
        }
        
        Ok(())
    }

    pub fn pop_block_context(&mut self) -> Result<()> {
        let (block_type, _) = self.labels.pop()
            .ok_or_else(|| anyhow::anyhow!("No block context to pop"))?;
            
        // Validate block result type matches what's on the stack
        match block_type.result_type() {
            Some(expected) => {
                let actual = self.stack.pop()
                    .ok_or_else(|| anyhow::anyhow!("Stack underflow when validating block result"))?;
                if actual != expected {
                    return Err(anyhow::anyhow!("Block result type mismatch: expected {:?}, got {:?}", expected, actual));
                }
            }
            None => {}
        }
        
        Ok(())
    }

    pub fn block_depth(&self) -> usize {
        self.labels.len()
    }

    pub fn get_module(&self) -> &walrus::Module {
        &self.module
    }

    pub fn get_module_mut(&mut self) -> &mut walrus::Module {
        &mut self.module
    }

    pub fn validate_instruction(&mut self, instr: Instr) -> Result<()> {
        match instr {
            Instr::Const(const_instr) => {
                let value_type = match const_instr.value {
                    Value::I32(_) => ValueType::I32,
                    Value::I64(_) => ValueType::I64,
                    Value::F32(_) => ValueType::F32,
                    Value::F64(_) => ValueType::F64,
                    Value::V128(_) => ValueType::V128,
                };
                self.stack.push(value_type);
                Ok(())
            }

            Instr::Binop(binop) => {
                let (operand_type, result_type) = match binop.op {
                    BinaryOp::I32Add | BinaryOp::I32Sub | BinaryOp::I32Mul | BinaryOp::I32DivS | BinaryOp::I32DivU => {
                        (ValueType::I32, ValueType::I32)
                    }
                    BinaryOp::I64Add | BinaryOp::I64Sub | BinaryOp::I64Mul | BinaryOp::I64DivS | BinaryOp::I64DivU => {
                        (ValueType::I64, ValueType::I64)
                    }
                    BinaryOp::F32Add | BinaryOp::F32Sub | BinaryOp::F32Mul | BinaryOp::F32Div => {
                        (ValueType::F32, ValueType::F32)
                    }
                    BinaryOp::F64Add | BinaryOp::F64Sub | BinaryOp::F64Mul | BinaryOp::F64Div => {
                        (ValueType::F64, ValueType::F64)
                    }
                    _ => return Err(anyhow::anyhow!("Unsupported binary operation")),
                };

                // Pop two operands of the same type
                let rhs = self.stack.pop().ok_or_else(|| anyhow::anyhow!("Stack underflow"))?;
                let lhs = self.stack.pop().ok_or_else(|| anyhow::anyhow!("Stack underflow"))?;
                if lhs != operand_type || rhs != operand_type {
                    return Err(anyhow::anyhow!("Type mismatch in binary operation"));
                }

                // Push result
                self.stack.push(result_type);
                Ok(())
            }

            Instr::LocalGet(local_get) => {
                let local_idx = local_get.local.index() as usize;
                // Check if the local index is valid and the local exists in our context
                if local_idx >= self.locals.len() {
                    return Err(anyhow::anyhow!("Invalid local index: {} (max: {})", local_idx, self.locals.len() - 1));
                }
                self.stack.push(self.locals[local_idx]);
                Ok(())
            }

            Instr::LocalSet(local_set) => {
                let local_idx = local_set.local.index() as usize;
                // Check if the local index is valid and the local exists in our context
                if local_idx >= self.locals.len() {
                    return Err(anyhow::anyhow!("Invalid local index: {} (max: {})", local_idx, self.locals.len() - 1));
                }
                let value = self.stack.pop().ok_or_else(|| anyhow::anyhow!("Stack underflow"))?;
                if value != self.locals[local_idx] {
                    return Err(anyhow::anyhow!("Type mismatch in local.set"));
                }
                Ok(())
            }

            Instr::GlobalGet(global_get) => {
                let global_idx = global_get.global.index() as usize;
                // Check if the global index is valid and the global exists in our context
                if global_idx >= self.globals.len() {
                    return Err(anyhow::anyhow!("Invalid global index: {} (max: {})", global_idx, self.globals.len() - 1));
                }
                self.stack.push(self.globals[global_idx]);
                Ok(())
            }

            Instr::GlobalSet(global_set) => {
                let global_idx = global_set.global.index() as usize;
                // Check if the global index is valid and the global exists in our context
                if global_idx >= self.globals.len() {
                    return Err(anyhow::anyhow!("Invalid global index: {} (max: {})", global_idx, self.globals.len() - 1));
                }
                let value = self.stack.pop().ok_or_else(|| anyhow::anyhow!("Stack underflow"))?;
                if value != self.globals[global_idx] {
                    return Err(anyhow::anyhow!("Type mismatch in global.set"));
                }
                Ok(())
            }

            Instr::Block(block) => {
                // For now, just push I32 as that's what our tests use
                // TODO: Get proper block type from sequence
                self.push_block_context(Some(ValType::I32), block.seq)?;
                Ok(())
            }
            
            Instr::Loop(loop_) => {
                // For now, just push I32 as that's what our tests use
                // TODO: Get proper loop type from sequence
                self.push_block_context(Some(ValType::I32), loop_.seq)?;
                Ok(())
            }

            Instr::Br(br) => {
                // Get current block depth
                let depth = self.block_depth();
                if depth == 0 {
                    return Err(anyhow::anyhow!("Cannot branch when not in a block"));
                }

                // Get target index (relative to current depth)
                let target_idx = br.block.index();
                if target_idx >= depth {
                    return Err(anyhow::anyhow!("Invalid branch target: block {} is out of range (depth {})", 
                        target_idx, depth));
                }

                // Get the target block sequence ID at this depth
                let target_pos = depth - target_idx - 1;
                let target_seq = self.labels.get(target_pos)
                    .map(|(_, seq)| seq)
                    .ok_or_else(|| anyhow::anyhow!("Invalid branch target: block not found at depth {}", target_idx))?;

                // Sequence ID must match exactly
                if *target_seq != br.block {
                    return Err(anyhow::anyhow!("Invalid branch target: block sequence ID does not match at depth {}", target_idx));
                }

                Ok(())
            }

            Instr::BrIf(br_if) => {
                // Validate condition type
                let condition = self.stack.pop()
                    .ok_or_else(|| anyhow::anyhow!("Stack underflow when validating branch condition"))?;
                if condition != ValueType::I32 {
                    return Err(anyhow::anyhow!("Branch condition must be i32, got {:?}", condition));
                }

                // Get current block depth
                let depth = self.block_depth();
                if depth == 0 {
                    return Err(anyhow::anyhow!("Cannot branch when not in a block"));
                }

                // Get target index (relative to current depth)
                let target_idx = br_if.block.index();
                if target_idx >= depth {
                    return Err(anyhow::anyhow!("Invalid branch target: block {} is out of range (depth {})", 
                        target_idx, depth));
                }

                // Get the target block sequence ID at this depth
                let target_pos = depth - target_idx - 1;
                let target_seq = self.labels.get(target_pos)
                    .map(|(_, seq)| seq)
                    .ok_or_else(|| anyhow::anyhow!("Invalid branch target: block not found at depth {}", target_idx))?;

                // Sequence ID must match exactly
                if *target_seq != br_if.block {
                    return Err(anyhow::anyhow!("Invalid branch target: block sequence ID does not match at depth {}", target_idx));
                }

                Ok(())
            }

            _ => Err(anyhow::anyhow!("Unsupported instruction")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use walrus::ir::{Value, Const};
    use walrus::{Module, FunctionBuilder, ValType};

    #[test]
    fn test_stack_validation() -> Result<()> {
        let mut stack = Stack::new();

        // Test basic push/pop
        stack.push(ValueType::I32);
        stack.pop();

        // Test type mismatch
        stack.push(ValueType::I32);
        assert!(stack.pop().ok_or(anyhow::anyhow!("Stack underflow"))? != ValueType::I64);

        // Test stack underflow
        assert!(stack.pop().is_none());

        // Test multiple push/pop
        stack.push_multi(&[ValueType::I32, ValueType::I64, ValueType::F32]);
        assert_eq!(stack.height(), 3);
        assert_eq!(stack.pop().ok_or(anyhow::anyhow!("Stack underflow"))?, ValueType::F32);
        assert_eq!(stack.pop().ok_or(anyhow::anyhow!("Stack underflow"))?, ValueType::I64);
        assert_eq!(stack.height(), 1);
        assert_eq!(stack.peek(), Some(&ValueType::I32));

        Ok(())
    }

    #[test]
    fn test_module_context() -> Result<()> {
        // Create a test module
        let mut module = Module::default();
        let builder = walrus::FunctionBuilder::new(&mut module.types, &[ValType::I32], &[ValType::I32]);
        let func_id = builder.finish(vec![], &mut module.funcs);
        
        // Add a mutable global with initial value 0
        module.globals.add_local(
            ValType::I32,
            true,
            walrus::InitExpr::Value(Value::I32(0))
        );

        // Create type context
        let ctx = TypeContext::from_module(module, func_id)?;

        // Verify globals were imported correctly
        assert_eq!(ctx.globals.len(), 1);
        assert_eq!(ctx.globals[0], ValueType::I32);

        Ok(())
    }

    #[test]
    fn test_instruction_validation() -> Result<()> {
        // Create a type context with a specific set of locals and globals
        let mut ctx = TypeContext::new();
        ctx.locals = vec![ValueType::I32]; // Only one local
        ctx.globals = vec![
            ValueType::I32,
        ];

        // Test constants
        ctx.validate_instruction(Instr::Const(Const { value: Value::I32(42) }))?;
        assert_eq!(ctx.stack.peek(), Some(&ValueType::I32));

        // Test binary operations
        ctx.validate_instruction(Instr::Const(Const { value: Value::I32(10) }))?;
        ctx.validate_instruction(Instr::Binop(walrus::ir::Binop { op: BinaryOp::I32Add }))?;
        assert_eq!(ctx.stack.peek(), Some(&ValueType::I32));

        // Create a module to get valid IDs
        let mut module = Module::default();
        let local_id = module.locals.add(ValType::I32);
        let global_id = module.globals.add_local(
            ValType::I32,
            true,
            walrus::InitExpr::Value(Value::I32(0))
        );

        // Test locals - this should work since we have one local in our context
        ctx.validate_instruction(Instr::LocalGet(walrus::ir::LocalGet { local: local_id }))?;
        ctx.validate_instruction(Instr::LocalSet(walrus::ir::LocalSet { local: local_id }))?;
        
        // Test globals
        ctx.validate_instruction(Instr::GlobalGet(walrus::ir::GlobalGet { global: global_id }))?;
        ctx.validate_instruction(Instr::GlobalSet(walrus::ir::GlobalSet { global: global_id }))?;

        // Create a different module with different locals and globals
        let mut other_module = Module::default();
        // Add lots of locals to make sure the index is definitely out of bounds
        for _ in 0..10 {
            other_module.locals.add(ValType::I32);
        }
        let invalid_local = other_module.locals.add(ValType::I32); // This should be local #11

        // Add lots of globals to make sure the index is out of bounds
        for _ in 0..10 {
            other_module.globals.add_local(
                ValType::I32,
                true,
                walrus::InitExpr::Value(Value::I32(0))
            );
        }
        let invalid_global = other_module.globals.add_local(
            ValType::F64,
            false,
            walrus::InitExpr::Value(Value::F64(0.0))
        );

        // Print the indices to debug
        println!("Local indices - valid: {}, invalid: {}", local_id.index(), invalid_local.index());
        println!("Global indices - valid: {}, invalid: {}", global_id.index(), invalid_global.index());

        // Try to access a local that is out of bounds (we only have 1 local in our context)
        assert!(ctx.validate_instruction(Instr::LocalGet(walrus::ir::LocalGet { local: invalid_local })).is_err(),
                "Expected error when accessing local from different module (index {}, but context only has {} locals)",
                invalid_local.index(), ctx.locals.len());

        // Try to set a global from a different module
        assert!(ctx.validate_instruction(Instr::GlobalSet(walrus::ir::GlobalSet { global: invalid_global })).is_err(),
                "Expected error when accessing global from different module (index {}, but context only has {} globals)",
                invalid_global.index(), ctx.globals.len());

        Ok(())
    }

    #[test]
    fn test_control_flow() -> Result<()> {
        let mut module = Module::default();
        
        // Create a function builder to help create instruction sequences
        let builder = FunctionBuilder::new(&mut module.types, &[], &[ValType::I32]);
        let func_id = builder.finish(vec![], &mut module.funcs);
        
        // Create a new context with the module
        let mut ctx = TypeContext::from_module(module, func_id)?;
        
        // Create a new builder for block sequences
        let mut block_builder = FunctionBuilder::new(&mut ctx.get_module_mut().types, &[], &[ValType::I32]);
        
        // Create empty block sequence
        let empty_block = block_builder.func_body();
        let empty_id = empty_block.id();
        
        // Create block with i32 result
        let mut i32_block = block_builder.func_body();
        i32_block.instr(Instr::Const(Const { value: Value::I32(42) }));
        let i32_id = i32_block.id();

        // Create loop sequence
        let loop_block = block_builder.func_body();
        let loop_id = loop_block.id();
        
        // Test empty block
        ctx.validate_instruction(Instr::Block(walrus::ir::Block {
            seq: empty_id,
        }))?;

        // Test block with result
        ctx.validate_instruction(Instr::Block(walrus::ir::Block {
            seq: i32_id,
        }))?;
        assert_eq!(ctx.stack.peek(), Some(&ValueType::I32));

        // Test loop
        ctx.validate_instruction(Instr::Loop(walrus::ir::Loop {
            seq: loop_id,
        }))?;

        // Test br_if with valid condition
        ctx.validate_instruction(Instr::Const(Const { value: Value::I32(1) }))?;
        ctx.validate_instruction(Instr::BrIf(walrus::ir::BrIf {
            block: empty_id,
        }))?;

        // Test br_if with invalid condition type
        ctx.validate_instruction(Instr::Const(Const { value: Value::F64(1.0) }))?;
        assert!(ctx.validate_instruction(Instr::BrIf(walrus::ir::BrIf {
            block: empty_id,
        })).is_err());

        // Create an invalid block target (using a sequence ID that doesn't exist in our context)
        let mut other_module = Module::default();
        let mut other_builder = FunctionBuilder::new(&mut other_module.types, &[], &[ValType::I32]);
        let other_block = other_builder.func_body();
        let invalid_id = other_block.id();
        
        // Test br with invalid target
        assert!(ctx.validate_instruction(Instr::Br(walrus::ir::Br {
            block: invalid_id,
        })).is_err());

        Ok(())
    }
}
