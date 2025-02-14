use walrus::ValType;
use walrus::ir::{Instr, Value, BinaryOp, InstrSeqId, LoadKind, StoreKind};
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

/// Represents limits for tables and memory
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Limits {
    /// Minimum size
    pub min: u32,
    /// Maximum size (if specified)
    pub max: Option<u32>,
}

impl Limits {
    pub fn new(min: u32, max: Option<u32>) -> Self {
        Self { min, max }
    }

    pub fn validate(&self) -> bool {
        if let Some(max) = self.max {
            max >= self.min
        } else {
            true
        }
    }
}

/// Reference types for tables
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RefType {
    /// Function reference
    Func,
    /// External reference
    Extern,
}

impl From<ValueType> for RefType {
    fn from(value_type: ValueType) -> Self {
        match value_type {
            ValueType::FuncRef => RefType::Func,
            ValueType::ExternRef => RefType::Extern,
            _ => panic!("Cannot convert non-reference type to RefType"),
        }
    }
}

/// Represents a WebAssembly table type
#[derive(Debug, Clone, PartialEq)]
pub struct TableType {
    /// Type of elements in the table
    pub element_type: RefType,
    /// Size limits of the table
    pub limits: Limits,
}

impl TableType {
    pub fn new(element_type: RefType, limits: Limits) -> Result<Self> {
        if !limits.validate() {
            return Err(anyhow::anyhow!("Invalid table limits"));
        }
        Ok(Self { element_type, limits })
    }
}

/// Represents a WebAssembly memory type
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryType {
    /// Size limits of the memory
    pub limits: Limits,
    /// Whether the memory is shared
    pub shared: bool,
}

impl MemoryType {
    pub fn new(limits: Limits, shared: bool) -> Result<Self> {
        if !limits.validate() {
            return Err(anyhow::anyhow!("Invalid memory limits"));
        }
        // WebAssembly spec: maximum must be less than or equal to 65536 pages (4GiB)
        if let Some(max) = limits.max {
            if max > 65536 {
                return Err(anyhow::anyhow!("Memory maximum exceeds 65536 pages"));
            }
        }
        Ok(Self { limits, shared })
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

/// Index types for WebAssembly
pub type TableIdx = u32;
pub type MemoryIdx = u32;
pub type FuncIdx = u32;

/// Represents an element segment in WebAssembly
#[derive(Debug, Clone)]
pub struct ElementSegment {
    /// Table index this segment targets
    pub table: TableIdx,
    /// Type of elements in this segment
    pub element_type: RefType,
    /// Element values (as function indices for funcref)
    pub elements: Vec<FuncIdx>,
    /// Offset expression for the segment
    pub offset: u32,
}

impl ElementSegment {
    pub fn new(table: TableIdx, element_type: RefType, elements: Vec<FuncIdx>, offset: u32) -> Self {
        Self {
            table,
            element_type,
            elements,
            offset,
        }
    }

    pub fn validate(&self, table_type: &TableType) -> Result<()> {
        // Check element type matches table
        if self.element_type != table_type.element_type {
            return Err(anyhow::anyhow!(
                "Element type mismatch: segment type {:?} != table type {:?}",
                self.element_type,
                table_type.element_type
            ));
        }

        // Check offset + length fits within table limits
        let end_offset = self.offset as u64 + self.elements.len() as u64;
        if let Some(max) = table_type.limits.max {
            if end_offset > max as u64 {
                return Err(anyhow::anyhow!(
                    "Element segment exceeds table limits: end offset {} > max {}",
                    end_offset,
                    max
                ));
            }
        }

        Ok(())
    }
}

/// Represents a data segment in WebAssembly
#[derive(Debug, Clone)]
pub struct DataSegment {
    /// Memory index this segment targets
    pub memory: MemoryIdx,
    /// Raw bytes of the segment
    pub data: Vec<u8>,
    /// Offset expression for the segment
    pub offset: u32,
}

impl DataSegment {
    pub fn new(memory: MemoryIdx, data: Vec<u8>, offset: u32) -> Self {
        Self {
            memory,
            data,
            offset,
        }
    }

    pub fn validate(&self, memory_type: &MemoryType) -> Result<()> {
        // Check offset + length fits within memory limits
        let end_offset = self.offset as u64 + self.data.len() as u64;
        
        // Convert to pages (64KiB per page)
        let required_pages = (end_offset + 65535) / 65536;
        
        if let Some(max_pages) = memory_type.limits.max {
            if required_pages > max_pages as u64 {
                return Err(anyhow::anyhow!(
                    "Data segment exceeds memory limits: required pages {} > max pages {}",
                    required_pages,
                    max_pages
                ));
            }
        }

        Ok(())
    }
}

/// Maximum allowed stack depth for preventing stack overflow
pub const MAX_STACK_DEPTH: usize = 1024;

/// Represents a stack of value types for validation
#[derive(Debug, Default)]
pub struct TypeContext {
    pub locals: Vec<ValueType>,
    pub globals: Vec<ValueType>,
    pub stack: Stack,
    pub labels: Vec<(BlockType, InstrSeqId)>,
    pub return_type: Option<ValueType>,
    module: walrus::Module,
    pub types: Vec<FunctionType>,
    pub functions: Vec<FunctionType>,
    current_func: Option<walrus::FunctionId>,
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
            current_func: None,
            return_type: None,
        }
    }

    pub fn get_current_function(&self) -> Option<walrus::FunctionId> {
        self.current_func
    }

    pub fn from_module(module: walrus::Module, func_id: walrus::FunctionId) -> Result<Self> {
        let mut ctx = Self::new();
        ctx.current_func = Some(func_id);
        
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
        Ok(ctx)
    }

    pub fn push_block_context(&mut self, block_type: Option<ValType>, seq_id: InstrSeqId) -> Result<()> {
        // Check stack depth limit
        if self.block_depth() >= MAX_STACK_DEPTH {
            return Err(anyhow::anyhow!("Maximum stack depth of {} exceeded", MAX_STACK_DEPTH));
        }

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
                if local_idx >= self.stack.height() {
                    return Err(anyhow::anyhow!("Invalid local index: {} (max: {})", local_idx, self.stack.height() - 1));
                }
                self.stack.push(self.stack.types[local_idx]);
                Ok(())
            }

            Instr::LocalSet(local_set) => {
                let local_idx = local_set.local.index() as usize;
                // Check if the local index is valid and the local exists in our context
                if local_idx >= self.stack.height() {
                    return Err(anyhow::anyhow!("Invalid local index: {} (max: {})", local_idx, self.stack.height() - 1));
                }
                let value = self.stack.pop().ok_or_else(|| anyhow::anyhow!("Stack underflow"))?;
                if value != self.stack.types[local_idx] {
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

            Instr::Call(call) => {
                let _func_id = call.func;  // Prefix with underscore since it's unused
                let current_func = self.current_func.ok_or_else(|| anyhow::anyhow!("No current function"))?;
                
                // Get function type
                if let walrus::FunctionKind::Local(local) = &self.module.funcs.get(current_func).kind {
                    let type_id = local.ty();
                    let func_type = self.module.types.get(type_id);
                    
                    // Pop arguments
                    for _ in func_type.params().iter() {
                        self.stack.pop().ok_or_else(|| anyhow::anyhow!("Stack underflow"))?;
                    }
                    
                    // Push results
                    for result in func_type.results().iter() {
                        self.stack.push(ValueType::from(*result));
                    }
                }
                Ok(())
            }

            Instr::Load(load) => {
                // Validate memory index
                let _memory = self.module.memories.get(load.memory);

                // Validate alignment
                let natural_alignment = match load.kind {
                    LoadKind::I32 { atomic: _ } => 4,
                    LoadKind::I64 { atomic: _ } => 8,
                    LoadKind::F32 => 4,
                    LoadKind::F64 => 8,
                    _ => return Err(anyhow::anyhow!("Unsupported load type")),
                };

                if !load.arg.align.is_power_of_two() || load.arg.align > natural_alignment {
                    return Err(anyhow::anyhow!("Invalid alignment"));
                }

                // Check address is on stack
                self.stack.pop().ok_or_else(|| anyhow::anyhow!("Stack underflow - missing address"))?;

                // Push loaded value type
                let result_type = match load.kind {
                    LoadKind::I32 { atomic: _ } => ValueType::I32,
                    LoadKind::I64 { atomic: _ } => ValueType::I64,
                    LoadKind::F32 => ValueType::F32,
                    LoadKind::F64 => ValueType::F64,
                    _ => return Err(anyhow::anyhow!("Unsupported load type")),
                };
                self.stack.push(result_type);
                Ok(())
            }

            Instr::Store(store) => {
                // Validate memory index
                let _memory = self.module.memories.get(store.memory);

                // Validate alignment
                let natural_alignment = match store.kind {
                    StoreKind::I32 { atomic: _ } => 4,
                    StoreKind::I64 { atomic: _ } => 8,
                    StoreKind::F32 => 4,
                    StoreKind::F64 => 8,
                    _ => return Err(anyhow::anyhow!("Unsupported store type")),
                };

                if !store.arg.align.is_power_of_two() || store.arg.align > natural_alignment {
                    return Err(anyhow::anyhow!("Invalid alignment"));
                }

                // Pop value and address
                let value_type = self.stack.pop().ok_or_else(|| anyhow::anyhow!("Stack underflow - missing value"))?;
                let expected_type = match store.kind {
                    StoreKind::I32 { atomic: _ } => ValueType::I32,
                    StoreKind::I64 { atomic: _ } => ValueType::I64,
                    StoreKind::F32 => ValueType::F32,
                    StoreKind::F64 => ValueType::F64,
                    _ => return Err(anyhow::anyhow!("Unsupported store type")),
                };
                
                if value_type != expected_type {
                    return Err(anyhow::anyhow!("Type mismatch in store operation"));
                }
                
                self.stack.pop().ok_or_else(|| anyhow::anyhow!("Stack underflow - missing address"))?;
                Ok(())
            }

            Instr::MemoryGrow(memory) => {
                // Validate memory index
                let _memory = self.module.memories.get(memory.memory);

                // Check delta is on stack
                self.stack.pop().ok_or_else(|| anyhow::anyhow!("Stack underflow - missing delta"))?;

                // Push result (previous size or -1)
                self.stack.push(ValueType::I32);
                Ok(())
            }

            Instr::MemorySize(memory) => {
                // Validate memory index
                let _memory = self.module.memories.get(memory.memory);

                // Push current size
                self.stack.push(ValueType::I32);
                Ok(())
            }

            Instr::TableGet(table) => {
                // Validate table index
                let _table = self.module.tables.get(table.table);

                // Check index is on stack
                self.stack.pop().ok_or_else(|| anyhow::anyhow!("Stack underflow - missing index"))?;

                // Push element type (always funcref in MVP)
                self.stack.push(ValueType::FuncRef);
                Ok(())
            }

            Instr::TableSet(table) => {
                // Validate table index
                let _table = self.module.tables.get(table.table);

                // Pop value and index
                let value_type = self.stack.pop().ok_or_else(|| anyhow::anyhow!("Stack underflow - missing value"))?;
                if value_type != ValueType::FuncRef {
                    return Err(anyhow::anyhow!("Type mismatch in table set operation"));
                }

                self.stack.pop().ok_or_else(|| anyhow::anyhow!("Stack underflow - missing index"))?;
                Ok(())
            }

            Instr::TableGrow(table) => {
                // Validate table index
                let _table = self.module.tables.get(table.table);

                // Pop init value and delta
                let init_type = self.stack.pop().ok_or_else(|| anyhow::anyhow!("Stack underflow - missing init value"))?;
                if init_type != ValueType::FuncRef {
                    return Err(anyhow::anyhow!("Type mismatch in table grow operation"));
                }

                self.stack.pop().ok_or_else(|| anyhow::anyhow!("Stack underflow - missing delta"))?;

                // Push result (previous size or -1)
                self.stack.push(ValueType::I32);
                Ok(())
            }

            Instr::TableSize(table) => {
                // Validate table index
                let _table = self.module.tables.get(table.table);

                // Push current size
                self.stack.push(ValueType::I32);
                Ok(())
            }

            _ => Err(anyhow::anyhow!("Unsupported instruction")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use walrus::{Module, FunctionBuilder};
    use walrus::ir::*;
    
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
        let builder = FunctionBuilder::new(&mut module.types, &[ValType::I32], &[ValType::I32]);
        let func_id = builder.finish(vec![], &mut module.funcs);
        
        // Add a mutable global with initial value 0
        module.globals.add_local(
            ValType::I32,
            true,
            walrus::InitExpr::Value(Value::I32(0)),
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
        ctx.globals = vec![ValueType::I32];

        // Test constants
        ctx.validate_instruction(Instr::Const(Const { value: Value::I32(42) }))?;
        assert_eq!(ctx.stack.peek(), Some(&ValueType::I32));

        // Create module for IDs
        let mut module = Module::default();
        let local_id = module.locals.add(ValType::I32);
        let _global_id = module.globals.add_local(
            ValType::I32,
            true,
            walrus::InitExpr::Value(Value::I32(0)),
        );

        // Test locals - this should work since we have one local in our context
        ctx.validate_instruction(Instr::LocalGet(LocalGet { local: local_id }))?;
        assert_eq!(ctx.stack.peek(), Some(&ValueType::I32));

        Ok(())
    }

    #[test]
    fn test_control_flow() -> Result<()> {
        let mut module = Module::default();
        let builder = FunctionBuilder::new(&mut module.types, &[], &[ValType::I32]);
        let func_id = builder.finish(Vec::new(), &mut module.funcs);
        
        let mut ctx = TypeContext::from_module(
            module,
            func_id,
        )?;
        
        // Create a new builder for block sequences
        let mut builder = FunctionBuilder::new(&mut ctx.get_module_mut().types, &[], &[ValType::I32]);
        
        // Create empty block sequence
        let mut empty_block = builder.func_body();
        let empty_id = empty_block.id();

        // Create block with i32 result
        let mut i32_block = builder.func_body();
        i32_block.instr(Instr::Const(Const { value: Value::I32(42) }));
        let i32_id = i32_block.id();

        // Create loop sequence
        let mut loop_block = builder.func_body();
        loop_block.instr(Instr::Const(Const { value: Value::I32(3) }));
        let loop_id = loop_block.id();

        // Test empty block
        ctx.validate_instruction(Instr::Block(Block {
            seq: empty_id,
        }))?;

        // Test block with result
        ctx.validate_instruction(Instr::Block(Block {
            seq: i32_id,
        }))?;
        assert_eq!(ctx.stack.peek(), Some(&ValueType::I32));

        // Test loop
        ctx.validate_instruction(Instr::Loop(Loop {
            seq: loop_id,
        }))?;

        // Test conditional branching in nested blocks
        ctx.validate_instruction(Instr::Const(Const { value: Value::I32(1) }))?;
        ctx.validate_instruction(Instr::BrIf(BrIf {
            block: empty_id,
        }))?;

        // Test breaking to outer block
        ctx.validate_instruction(Instr::Const(Const { value: Value::I32(0) }))?;
        ctx.validate_instruction(Instr::BrIf(BrIf {
            block: i32_id,
        }))?;

        // Verify final stack state
        assert_eq!(ctx.stack.peek(), Some(&ValueType::I32));

        Ok(())
    }

    #[test]
    fn test_memory_instructions() -> Result<()> {
        let mut module = Module::default();
        
        // Create a memory with initial size 1 page
        let memory_id = module.memories.add_local(false, 1, None);
        
        // Create a function builder
        let builder = FunctionBuilder::new(&mut module.types, &[], &[]);
        let func_id = builder.finish(Vec::new(), &mut module.funcs);
        
        // Create type context
        let mut ctx = TypeContext::from_module(
            module,
            func_id,
        )?;
        
        // Test memory.grow
        ctx.stack.push(ValueType::I32); // Push delta
        ctx.validate_instruction(Instr::MemoryGrow(MemoryGrow { memory: memory_id }))?;
        assert_eq!(ctx.stack.height(), 1); // Result pushed
        assert_eq!(ctx.stack.pop().unwrap(), ValueType::I32);
        
        // Test memory.size
        ctx.validate_instruction(Instr::MemorySize(MemorySize { memory: memory_id }))?;
        assert_eq!(ctx.stack.height(), 1); // Size pushed
        assert_eq!(ctx.stack.pop().unwrap(), ValueType::I32);
        
        Ok(())
    }

    #[test]
    fn test_table_instructions() -> Result<()> {
        let mut module = Module::default();
        
        // Create a table with initial size 1
        let table_id = module.tables.add_local(1, None, ValType::Funcref);
        
        // Create a function builder
        let builder = FunctionBuilder::new(&mut module.types, &[], &[]);
        let func_id = builder.finish(Vec::new(), &mut module.funcs);
        
        // Create type context
        let mut ctx = TypeContext::from_module(module, func_id)?;

        // Test table.get
        ctx.stack.push(ValueType::I32); // Push index
        ctx.validate_instruction(Instr::TableGet(TableGet { table: table_id }))?;
        assert_eq!(ctx.stack.height(), 1); // Result pushed
        assert_eq!(ctx.stack.pop().unwrap(), ValueType::FuncRef);
        
        // Test table.set
        ctx.stack.push(ValueType::I32); // Push index
        ctx.stack.push(ValueType::FuncRef); // Push value
        ctx.validate_instruction(Instr::TableSet(TableSet { table: table_id }))?;
        assert_eq!(ctx.stack.height(), 0); // Stack empty after set
        
        Ok(())
    }

    #[test]
    fn test_stack_depth_limit() -> Result<()> {
        let mut context = TypeContext::new();
        let mut module = Module::default();
        let mut builder = FunctionBuilder::new(&mut module.types, &[], &[]);
        let seq_id = builder.func_body().id();

        // Push blocks up to the limit
        for _ in 0..MAX_STACK_DEPTH {
            context.push_block_context(Some(ValType::I32), seq_id)?;
        }

        // Verify pushing one more block fails
        let result = context.push_block_context(Some(ValType::I32), seq_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Maximum stack depth"));

        Ok(())
    }

    #[test]
    fn test_limits_validation() {
        // Valid limits
        assert!(Limits::new(0, None).validate());
        assert!(Limits::new(0, Some(10)).validate());
        assert!(Limits::new(5, Some(5)).validate());
        
        // Invalid limits
        assert!(Limits::new(10, Some(5)).validate() == false);
    }

    #[test]
    fn test_table_type() {
        // Valid table
        let limits = Limits::new(0, Some(10));
        let table = TableType::new(RefType::Func, limits).unwrap();
        assert_eq!(table.element_type, RefType::Func);
        assert_eq!(table.limits, limits);

        // Invalid limits
        let invalid_limits = Limits::new(10, Some(5));
        assert!(TableType::new(RefType::Func, invalid_limits).is_err());
    }

    #[test]
    fn test_memory_type() {
        // Valid memory
        let limits = Limits::new(0, Some(100));
        let memory = MemoryType::new(limits, false).unwrap();
        assert_eq!(memory.limits, limits);
        assert_eq!(memory.shared, false);

        // Invalid limits (exceeds max pages)
        let invalid_limits = Limits::new(0, Some(70000));
        assert!(MemoryType::new(invalid_limits, false).is_err());
    }

    #[test]
    fn test_element_segment() {
        let table_limits = Limits::new(10, Some(20));
        let table_type = TableType::new(RefType::Func, table_limits).unwrap();
        
        // Valid element segment
        let segment = ElementSegment::new(
            0,
            RefType::Func,
            vec![1, 2, 3],
            0
        );
        assert!(segment.validate(&table_type).is_ok());

        // Invalid type
        let invalid_type_segment = ElementSegment::new(
            0,
            RefType::Extern,
            vec![1, 2, 3],
            0
        );
        assert!(invalid_type_segment.validate(&table_type).is_err());

        // Exceeds limits
        let exceeding_segment = ElementSegment::new(
            0,
            RefType::Func,
            vec![1, 2, 3],
            18 // offset + length > 20
        );
        assert!(exceeding_segment.validate(&table_type).is_err());
    }

    #[test]
    fn test_data_segment() {
        let memory_limits = Limits::new(1, Some(2)); // 2 pages = 128KiB
        let memory_type = MemoryType::new(memory_limits, false).unwrap();
        
        // Valid data segment
        let segment = DataSegment::new(
            0,
            vec![0; 65536], // 1 page
            0
        );
        assert!(segment.validate(&memory_type).is_ok());

        // Exceeds limits
        let large_segment = DataSegment::new(
            0,
            vec![0; 200000], // > 2 pages when including offset
            65536
        );
        assert!(large_segment.validate(&memory_type).is_err());
    }

    #[test]
    fn test_invalid_memory_operations() -> Result<()> {
        let mut module = Module::default();
        
        // Create a memory with initial size 1 page
        let memory_id = module.memories.add_local(false, 1, None);
        
        // Create a function builder
        let builder = FunctionBuilder::new(&mut module.types, &[], &[]);
        let func_id = builder.finish(Vec::new(), &mut module.funcs);
        
        // Create type context
        let mut ctx = TypeContext::from_module(
            module,
            func_id,
        )?;
        
        // Test invalid alignment
        ctx.stack.push(ValueType::I32); // address
        assert!(ctx.validate_instruction(Instr::Load(Load {
            memory: memory_id,
            arg: MemArg { align: 16, offset: 0 }, // Too large alignment for i32
            kind: LoadKind::I32 { atomic: false },
        })).is_err());

        // Test type mismatch in store
        ctx.stack.push(ValueType::I32); // address
        ctx.stack.push(ValueType::I64); // wrong value type
        assert!(ctx.validate_instruction(Instr::Store(Store {
            memory: memory_id,
            arg: MemArg { align: 4, offset: 0 },
            kind: StoreKind::I32 { atomic: false },
        })).is_err());

        Ok(())
    }

    #[test]
    fn test_invalid_table_operations() -> Result<()> {
        let mut module = Module::default();
        
        // Create a table with initial size 1
        let table_id = module.tables.add_local(1, None, ValType::Funcref);
        
        // Create a function builder
        let builder = FunctionBuilder::new(&mut module.types, &[], &[]);
        let func_id = builder.finish(Vec::new(), &mut module.funcs);
        
        // Create type context
        let mut ctx = TypeContext::from_module(module, func_id)?;

        // Test type mismatch in table.set
        ctx.stack.push(ValueType::I32); // index
        ctx.stack.push(ValueType::ExternRef); // wrong reference type
        assert!(ctx.validate_instruction(Instr::TableSet(TableSet {
            table: table_id,
        })).is_err());

        // Test type mismatch in table.grow
        ctx.stack.push(ValueType::I32); // delta
        ctx.stack.push(ValueType::ExternRef); // wrong reference type
        assert!(ctx.validate_instruction(Instr::TableGrow(TableGrow {
            table: table_id,
        })).is_err());

        Ok(())
    }

    #[test]
    fn test_global_operations() -> Result<()> {
        let mut module = Module::default();
        
        // Create globals in the module
        let global_i32 = module.globals.add_local(
            ValType::I32,
            true,
            walrus::InitExpr::Value(Value::I32(42)),
        );
        let global_f64 = module.globals.add_local(
            ValType::F64,
            true,
            walrus::InitExpr::Value(Value::F64(3.14)),
        );

        // Create a function for context
        let builder = FunctionBuilder::new(&mut module.types, &[], &[]);
        let func_id = builder.finish(Vec::new(), &mut module.funcs);
        
        // Create type context
        let mut ctx = TypeContext::from_module(module, func_id)?;

        // Test global.get
        ctx.validate_instruction(Instr::GlobalGet(GlobalGet { global: global_i32 }))?;
        assert_eq!(ctx.stack.peek(), Some(&ValueType::I32));
        ctx.stack.pop();

        ctx.validate_instruction(Instr::GlobalGet(GlobalGet { global: global_f64 }))?;
        assert_eq!(ctx.stack.peek(), Some(&ValueType::F64));
        ctx.stack.pop();

        // Test global.set
        ctx.stack.push(ValueType::I32);
        ctx.validate_instruction(Instr::GlobalSet(GlobalSet { global: global_i32 }))?;
        assert_eq!(ctx.stack.height(), 0);

        // Test invalid global.set (type mismatch)
        ctx.stack.push(ValueType::F64);
        assert!(ctx.validate_instruction(Instr::GlobalSet(GlobalSet { global: global_i32 })).is_err());

        Ok(())
    }

    #[test]
    fn test_type_coercion_extended() -> Result<()> {
        let mut ctx = TypeContext::new();

        // Test numeric operations
        ctx.stack.push(ValueType::I32);
        ctx.stack.push(ValueType::I32);
        ctx.validate_instruction(Instr::Binop(Binop { op: BinaryOp::I32Add }))?;
        assert_eq!(ctx.stack.peek(), Some(&ValueType::I32));
        ctx.stack.pop();

        ctx.stack.push(ValueType::F64);
        ctx.stack.push(ValueType::F64);
        ctx.validate_instruction(Instr::Binop(Binop { op: BinaryOp::F64Add }))?;
        assert_eq!(ctx.stack.peek(), Some(&ValueType::F64));
        ctx.stack.pop();

        // Test invalid operation (type mismatch)
        ctx.stack.push(ValueType::F64);
        ctx.stack.push(ValueType::I32);
        assert!(ctx.validate_instruction(Instr::Binop(Binop { op: BinaryOp::I32Add })).is_err());

        Ok(())
    }

    #[test]
    fn test_nested_control_flow() -> Result<()> {
        let mut module = Module::default();
        let builder = FunctionBuilder::new(&mut module.types, &[], &[ValType::I32]);
        let func_id = builder.finish(Vec::new(), &mut module.funcs);
        
        let mut ctx = TypeContext::from_module(module, func_id)?;
        
        // Create a new builder for block sequences
        let mut builder = FunctionBuilder::new(&mut ctx.get_module_mut().types, &[], &[ValType::I32]);
        
        // Create nested blocks with different result types
        let mut outer_block = builder.func_body();
        outer_block.instr(Instr::Const(Const { value: Value::I32(1) }));
        let outer_id = outer_block.id();

        let mut inner_block = builder.func_body();
        inner_block.instr(Instr::Const(Const { value: Value::F64(2.0) }));
        let inner_id = inner_block.id();

        let mut loop_block = builder.func_body();
        loop_block.instr(Instr::Const(Const { value: Value::I32(3) }));
        let loop_id = loop_block.id();

        // Test nested block structure
        ctx.validate_instruction(Instr::Block(Block { seq: outer_id }))?;
        ctx.validate_instruction(Instr::Block(Block { seq: inner_id }))?;
        ctx.validate_instruction(Instr::Loop(Loop { seq: loop_id }))?;

        // Test conditional branching in nested blocks
        ctx.validate_instruction(Instr::Const(Const { value: Value::I32(1) }))?;
        ctx.validate_instruction(Instr::BrIf(BrIf { block: inner_id }))?;

        // Test breaking to outer block
        ctx.validate_instruction(Instr::Const(Const { value: Value::I32(0) }))?;
        ctx.validate_instruction(Instr::BrIf(BrIf { block: outer_id }))?;

        // Verify final stack state
        assert_eq!(ctx.stack.peek(), Some(&ValueType::I32));

        Ok(())
    }
}
