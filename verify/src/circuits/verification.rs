use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError,
};
use std::marker::PhantomData;
use crate::parser::{
    WasmAnalyzer,
    ResourceUsage,
    ControlFlowGraph,
};
use crate::circuits::{
    memory_safety::MemorySafetyCircuit,
    type_safety::{TypeSafetyCircuit, BlockContext, StackOp},
    resource_bounds::ResourceBoundsCircuit,
    control_flow::ControlFlowCircuit,
};
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct PCDState<F: Field> {
    /// Memory access patterns
    pub memory_accesses: Vec<(u32, u32)>,
    /// Memory allocations
    pub allocations: Vec<(u32, u32)>,
    /// Stack operations
    pub stack_ops: Vec<StackOp>,
    /// Block contexts
    pub block_contexts: Vec<BlockContext>,
    /// Resource usage statistics
    pub resource_usage: ResourceUsage,
    /// Control flow graph
    pub call_graph: ControlFlowGraph,
    /// Phantom data
    _marker: PhantomData<F>,
}

impl<F: Field> PCDState<F> {
    pub fn new(
        memory_accesses: Vec<(u32, u32)>,
        allocations: Vec<(u32, u32)>,
        stack_ops: Vec<StackOp>,
        block_contexts: Vec<BlockContext>,
        resource_usage: ResourceUsage,
        call_graph: ControlFlowGraph,
    ) -> Self {
        Self {
            memory_accesses,
            allocations,
            stack_ops,
            block_contexts,
            resource_usage,
            call_graph,
            _marker: PhantomData,
        }
    }

    pub fn validate_state_transition(&self, next_state: &PCDState<F>) -> Result<()> {
        // Validate memory accesses are valid transitions
        for (curr_access, next_access) in self.memory_accesses.iter().zip(next_state.memory_accesses.iter()) {
            if curr_access.0 > next_access.0 {
                anyhow::bail!("Invalid memory access transition");
            }
        }

        // Validate stack operations
        if !self.stack_ops.is_empty() && !next_state.stack_ops.is_empty() {
            let last_op = &self.stack_ops[self.stack_ops.len() - 1];
            let first_op = &next_state.stack_ops[0];
            match (last_op, first_op) {
                (StackOp::Push(_), StackOp::Pop(_)) => {} // Valid transition
                _ => anyhow::bail!("Invalid stack operation transition"),
            }
        }

        // Validate resource usage
        if self.resource_usage.max_stack_depth > next_state.resource_usage.max_stack_depth {
            anyhow::bail!("Invalid stack depth transition");
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct VerificationCircuit<F: Field> {
    /// Previous state
    prev_state: Option<PCDState<F>>,
    /// Current state
    curr_state: Option<PCDState<F>>,
    /// Memory safety circuit
    memory_safety: MemorySafetyCircuit<F>,
    /// Type safety circuit
    type_safety: TypeSafetyCircuit<F>,
    /// Resource bounds circuit
    resource_bounds: ResourceBoundsCircuit<F>,
    /// Control flow circuit
    control_flow: ControlFlowCircuit<F>,
}

impl<F: Field> VerificationCircuit<F> {
    pub fn new(
        analyzer: &WasmAnalyzer,
        prev_state: Option<PCDState<F>>,
    ) -> Result<Self> {
        // Get memory ID
        let memory_id = analyzer.get_memory()
            .ok_or_else(|| anyhow::anyhow!("No memory found"))?;

        // Get memory type and current pages
        let memory_type = analyzer.get_memory_type(memory_id)?;
        let current_pages = analyzer.get_current_pages(memory_id);

        // Get memory accesses and initializations
        let memory_accesses = analyzer.get_memory_accesses_circuit(memory_id)
            .unwrap_or_default();
        let memory_inits = analyzer.get_memory_inits(memory_id)
            .unwrap_or_default();

        // Get stack operations and block contexts
        let stack_ops: Vec<StackOp> = analyzer.get_stack_ops()
            .unwrap_or_default()
            .into_iter()
            .map(|vt| StackOp::Push(vt))
            .collect();
        let block_contexts = analyzer.get_block_contexts()
            .unwrap_or_default();

        // Get call graph
        let call_graph = analyzer.get_call_graph()
            .unwrap_or_default();

        // Create current state
        let curr_state = Some(PCDState::new(
            analyzer.get_memory_access(memory_id).unwrap_or_default(),
            analyzer.get_memory_allocations(memory_id).unwrap_or_default(),
            stack_ops.clone(),
            block_contexts.clone(),
            analyzer.get_resource_usage(),
            call_graph.clone(),
        ));

        // Validate state transition if previous state exists
        if let (Some(prev), Some(curr)) = (&prev_state, &curr_state) {
            prev.validate_state_transition(curr)?;
        }

        // Create circuit components
        let memory_safety = MemorySafetyCircuit::new(
            memory_accesses,
            memory_inits,
            memory_type,
            current_pages,
        );

        let type_safety = TypeSafetyCircuit::new(
            stack_ops,
            block_contexts,
            Vec::new(), // Expected final stack
        );

        let resource_usage = analyzer.get_resource_usage();
        let resource_bounds = ResourceBoundsCircuit::new(
            resource_usage.max_stack_depth,
            resource_usage.max_call_depth,
            16, // Default max loop iterations
            resource_usage.max_table_size,
        );

        let control_flow = ControlFlowCircuit::new(
            call_graph,
            resource_usage.max_call_depth as usize,
            Vec::new(), // Expected edges
            Vec::new(), // Expected calls
        );

        Ok(Self {
            prev_state,
            curr_state,
            memory_safety,
            type_safety,
            resource_bounds,
            control_flow,
        })
    }
}

impl<F: Field> ConstraintSynthesizer<F> for VerificationCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Generate constraints for each component
        self.memory_safety.generate_constraints(cs.clone())?;
        self.type_safety.generate_constraints(cs.clone())?;
        self.resource_bounds.generate_constraints(cs.clone())?;
        self.control_flow.generate_constraints(cs)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_relations::r1cs::ConstraintSystem;
    use walrus::{Module, ModuleConfig};
    use std::path::PathBuf;
    use std::fs;
    use crate::parser::types::ValueType;
    use crate::circuits::type_safety::{StackOp, BlockContext};

    fn create_test_module() -> Result<Module> {
        let test_wasm_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test.wasm");
        let wasm_bytes = fs::read(test_wasm_path)?;
        let config = ModuleConfig::new();
        let module = config.parse(&wasm_bytes)?;
        Ok(module)
    }

    #[test]
    fn test_memory_safety_verification() -> Result<()> {
        // Create and analyze test module
        let module = create_test_module()?;
        let mut analyzer = WasmAnalyzer::new(module)?;
        analyzer.analyze()?;

        // Get the current state from the analyzer
        let memory_id = analyzer.get_memory().expect("Module should have memory");
        let memory_accesses = analyzer.get_memory_access(memory_id)
            .unwrap_or_default();
        let memory_allocations = analyzer.get_memory_allocations(memory_id)
            .unwrap_or_default();
        
        // Create empty stack operations since this test focuses on memory
        let stack_ops = Vec::new();
        let block_contexts = Vec::new();
        
        let resource_usage = analyzer.get_resource_usage();
        let call_graph = analyzer.get_call_graph()
            .unwrap_or_default();

        // Create state from analyzer data
        let state = PCDState::new(
            memory_accesses,
            memory_allocations,
            stack_ops,
            block_contexts,
            resource_usage,
            call_graph,
        );

        // Create circuit with the state
        let circuit = VerificationCircuit::<Fr>::new(
            &analyzer,
            Some(state),
        )?;

        // Generate and verify constraints
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs)?;

        Ok(())
    }

    #[test]
    fn test_type_safety_with_stack_ops() -> Result<()> {
        // Create and analyze test module
        let module = create_test_module()?;
        let mut analyzer = WasmAnalyzer::new(module)?;
        analyzer.analyze()?;

        // Get the current state from the analyzer
        let memory_id = analyzer.get_memory().expect("Module should have memory");
        let memory_accesses = analyzer.get_memory_access(memory_id)
            .unwrap_or_default();
        let memory_allocations = analyzer.get_memory_allocations(memory_id)
            .unwrap_or_default();
        
        // Create stack operations for testing type safety
        let stack_ops = vec![
            StackOp::Push(ValueType::I32),   // Push first operand
            StackOp::Push(ValueType::I32),   // Push second operand
            StackOp::Pop(ValueType::I32),    // Pop result of add operation
        ];
        
        // Create block context for testing
        let block_contexts = vec![
            BlockContext {
                param_types: vec![],
                result_types: vec![ValueType::I32],
                stack_height: 1,
            }
        ];
        
        let resource_usage = analyzer.get_resource_usage();
        let call_graph = analyzer.get_call_graph()
            .unwrap_or_default();

        // Create state from analyzer data
        let state = PCDState::new(
            memory_accesses,
            memory_allocations,
            stack_ops,
            block_contexts,
            resource_usage,
            call_graph,
        );

        // Create circuit with the state
        let circuit = VerificationCircuit::<Fr>::new(
            &analyzer,
            Some(state),
        )?;

        // Generate and verify constraints
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs)?;

        Ok(())
    }

    #[test]
    fn test_resource_bounds() -> Result<()> {
        // Create and analyze test module
        let module = create_test_module()?;
        let mut analyzer = WasmAnalyzer::new(module)?;
        analyzer.analyze()?;

        // Get the current state from the analyzer
        let memory_id = analyzer.get_memory().expect("Module should have memory");
        let memory_accesses = analyzer.get_memory_access(memory_id)
            .unwrap_or_default();
        let memory_allocations = analyzer.get_memory_allocations(memory_id)
            .unwrap_or_default();
        
        // Create empty stack operations since this test focuses on resource bounds
        let stack_ops = Vec::new();
        let block_contexts = Vec::new();
        
        let resource_usage = analyzer.get_resource_usage();
        let call_graph = analyzer.get_call_graph()
            .unwrap_or_default();

        // Create state from analyzer data
        let state = PCDState::new(
            memory_accesses,
            memory_allocations,
            stack_ops,
            block_contexts,
            resource_usage,
            call_graph,
        );

        // Create circuit with the state
        let circuit = VerificationCircuit::<Fr>::new(
            &analyzer,
            Some(state),
        )?;

        // Generate and verify constraints
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs)?;

        Ok(())
    }
}
