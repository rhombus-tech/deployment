use anyhow::Result;
use ark_bls12_381::Fr;
use std::collections::HashMap;
use walrus::{Module, ModuleConfig, FunctionId, TableId, ValType, InitExpr, ElementKind};
use crate::circuits::control_flow::ControlFlowCircuit;
use crate::parser::wasm_analyzer::WasmAnalyzer;
use crate::parser::FunctionTableInfo;

#[test]
fn test_indirect_call_walrus_api_integration() -> Result<()> {
    // Create a WASM module with functions and a table for indirect calls
    let wasm_bytes = create_test_module_with_table()?;
    
    // Create a WasmAnalyzer and parse the module
    let analyzer = WasmAnalyzer::from_bytes(&wasm_bytes)?;
    
    // Get the function tables using the parser with the walrus API
    let tables = analyzer.get_function_tables()?;
    assert!(!tables.is_empty(), "Module should have at least one function table");
    
    let table_info = &tables[0];
    println!("Table info: size = {}", table_info.elements.len());
    assert!(table_info.is_initialized, "Table should be initialized");
    
    // Prepare data for the ControlFlowCircuit
    let function_table_sizes = vec![table_info.elements.len()];
    
    // Convert the function table data to the format expected by the circuit
    let mut function_table_elements = HashMap::new();
    let mut function_types = HashMap::new();
    
    // Populate function elements and types from the parsed table
    for i in 0..table_info.elements.len() as u32 {
        if let Some(func_ref) = table_info.get_element(i) {
            println!("Table[{}] = func_idx: {}, type_idx: {}", i, func_ref.function_idx, func_ref.type_idx);
            function_table_elements.insert((0, i as usize), func_ref.function_idx as usize);
            function_types.insert(func_ref.function_idx as usize, func_ref.type_idx as usize);
        }
    }
    
    // Create the control flow circuit with the data from the parser
    let mut circuit = ControlFlowCircuit::<Fr>::new(
        Default::default(),
        15, // max call depth
        vec![],
        vec![],
        function_table_sizes.clone(),
        function_table_elements.clone(),
        function_types.clone(),
    );
    
    // Test valid indirect call
    if !function_table_elements.is_empty() {
        let (_, first_idx) = *function_table_elements.keys().next().unwrap();
        let result = circuit.validate_indirect_call(0, first_idx, 0);
        assert!(result.is_ok(), "Valid indirect call should succeed: {}", result.unwrap_err());
        
        // Test invalid table index
        let result = circuit.validate_indirect_call(1, first_idx, 0);
        assert!(result.is_err(), "Call with invalid table index should fail");
        
        // Test out of bounds element index
        let invalid_elem_idx = table_info.elements.len();
        let result = circuit.validate_indirect_call(0, invalid_elem_idx, 0);
        assert!(result.is_err(), "Call with out of bounds element should fail");
    }
    
    // Test call depth limits
    if !function_table_elements.is_empty() {
        let (_, first_idx) = *function_table_elements.keys().next().unwrap();
        
        // Start a series of calls to reach max depth
        // The ControlFlowCircuit doesn't have push_call_frame directly
        // But each call increases depth, so we'll track depth manually
        let mut current_depth = 0;
        
        // First call at depth 0
        let result = circuit.validate_indirect_call(0, first_idx, 0);
        assert!(result.is_ok(), "Call at depth 0 should succeed");
        current_depth += 1;
        
        // Tests at deeper levels can be simulated by manipulating circuit.current_depth directly
        // Or by actually making successive indirect calls
        // For now, we'll just test the boundary conditions with one valid and one invalid call
        
        // Set depth to just below max
        circuit.current_depth = 14; // Just below max of 15
        
        // One more valid call should succeed (depth 14 -> call valid)
        let result = circuit.validate_indirect_call(0, first_idx, 0);
        assert!(result.is_ok(), "Call at depth < max should succeed");
        
        // Set to max depth
        circuit.current_depth = 15; // At max
        
        // Call at max depth should fail
        let result = circuit.validate_indirect_call(0, first_idx, 0);
        assert!(result.is_err(), "Call at max depth should fail");
    }
    
    Ok(())
}

/// Create a test WASM module with functions and a table for indirect calls
fn create_test_module_with_table() -> Result<Vec<u8>> {
    // Create a new module
    let mut module = Module::default();
    
    // Add memory
    let memory_id = module.memories.add_local(false, 1, Some(1));
    module.exports.add("memory", memory_id);
    
    // Add a table for function references (fix parameter order)
    let table_id = module.tables.add_local(4, Some(10), ValType::Funcref);
    module.exports.add("table", table_id);
    
    // Create a type for our functions (no params, no results)
    let type_id = module.types.add(&[], &[]);
    
    // Create several functions with the same signature
    let mut function_ids = Vec::new();
    for i in 0..4 {
        let mut func = walrus::FunctionBuilder::new(&mut module.types, &[], &[]);
        let func_body = func.func_body();
        // Just return, no body needed for this test
        let func_id = func.finish(vec![], &mut module.funcs);
        
        // Export the function
        module.exports.add(&format!("func{}", i), func_id);
        function_ids.push(func_id);
    }
    
    // Create an element segment with updated API
    // In newer walrus, we have to create the element section differently
    let members: Vec<Option<FunctionId>> = function_ids.iter().map(|id| Some(*id)).collect();
    
    // Create and add the element segment with the new API
    let elem_id = module.elements.add(
        ElementKind::Passive,  // Initially create as passive
        ValType::Funcref,     // The type of element
        members,              // Function references
    );
    
    // Set the element as active (initialization for a specific table)
    module.elements.get_mut(elem_id).kind = ElementKind::Active {
        table: table_id,
        offset: InitExpr::Value(walrus::ir::Value::I32(0)),
    };
    
    // Serialize the module to bytes
    let wasm_bytes = module.emit_wasm();
    
    Ok(wasm_bytes)
}
