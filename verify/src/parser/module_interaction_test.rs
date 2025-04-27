use anyhow::Result;
use ark_bls12_381::Fr;
use std::collections::{HashMap, HashSet};
use walrus::{Module, ImportKind, ValType, ExportItem, InitExpr, ElementKind, FunctionId, LocalId, InstrSeqBuilder};
use walrus::ir::BinaryOp;
use crate::circuits::module_interaction::ModuleInteractionCircuit;
use crate::parser::module_interaction_analyzer::ModuleInteractionAnalyzer;

#[test]
fn test_cross_module_validation() -> Result<()> {
    // Create two test modules: a caller and a callee
    let callee_bytes = create_callee_module()?;
    let caller_bytes = create_caller_module_with_good_validation()?;
    
    // Analyze the callee module
    let callee_analyzer = ModuleInteractionAnalyzer::new(&callee_bytes, "callee")?;
    let callee_exports = callee_analyzer.extract_exports();
    
    // Make sure our callee module has exports
    assert!(!callee_exports.is_empty(), "Callee should have at least one export");
    
    // Analyze the caller module
    let mut caller_analyzer = ModuleInteractionAnalyzer::new(&caller_bytes, "caller")?;
    let imports = caller_analyzer.extract_imports();
    
    // Make sure our caller imports from the callee
    assert!(!imports.is_empty(), "Caller should have at least one import");
    assert_eq!(imports[0].module_name, "callee", "Import should be from the callee module");
    
    // Load and analyze function bodies for parameter validation
    caller_analyzer.load_function_bodies()?;
    let parameter_validations = caller_analyzer.analyze_parameter_validation();
    
    // Create a set of known modules
    let mut known_modules = HashSet::new();
    known_modules.insert("callee".to_string());
    
    // Create the validation circuit
    let mut circuit = ModuleInteractionCircuit::<Fr>::new(
        imports,
        known_modules.clone(), // Clone here to avoid ownership issues
        parameter_validations,
        1024, // Maximum reasonable parameter length
    );
    
    // Analyze the dependencies
    circuit.analyze_dependencies();
    
    // Validate the module interactions
    let result = circuit.validate_known_imports();
    assert!(result.is_ok(), "All imports should be from known modules");
    
    // Validate that there are no circular dependencies
    let result = circuit.validate_no_circular_dependencies();
    assert!(result.is_ok(), "There should be no circular dependencies");
    
    // Validate parameter handling
    let result = circuit.validate_parameter_handling();
    assert!(result.is_ok(), "All parameter handling should be valid");
    
    // Test with a bad caller that doesn't validate parameters
    let bad_caller_bytes = create_caller_module_with_bad_validation()?;
    let mut bad_caller_analyzer = ModuleInteractionAnalyzer::new(&bad_caller_bytes, "bad_caller")?;
    
    // Extract imports from the bad caller
    let bad_imports = bad_caller_analyzer.extract_imports();
    
    // Load and analyze function bodies
    bad_caller_analyzer.load_function_bodies()?;
    let bad_parameter_validations = bad_caller_analyzer.analyze_parameter_validation();
    
    // Create the bad caller
    let bad_circuit = ModuleInteractionCircuit::<Fr>::new(
        bad_imports,
        known_modules, // Removed clone here
        bad_parameter_validations,
        1024,
    );
    
    // Parameter validation should fail for the bad caller
    let result = bad_circuit.validate_parameter_handling();
    assert!(result.is_err(), "Validation should fail for the bad caller");
    
    // The error should mention missing length validation
    if let Err(e) = result {
        assert!(e.to_string().contains("does not validate"), 
                "Error should mention missing validation: {}", e);
    }
    
    Ok(())
}

/// Create a callee module with an exported function
fn create_callee_module() -> Result<Vec<u8>> {
    let mut module = Module::default();
    
    // Add memory (required for WebAssembly modules)
    let memory_id = module.memories.add_local(false, 1, Some(1));
    module.exports.add("memory", memory_id);
    
    // Add a type for the function, unused since we specify types directly in FunctionBuilder
    let _func_type = module.types.add(&[ValType::I32], &[ValType::I32]);
    
    // Create function with builder pattern
    let mut func_builder = walrus::FunctionBuilder::new(&mut module.types, &[ValType::I32], &[ValType::I32]);
    
    // We don't need to create locals for parameters as they're automatically created
    // Just return the constant 42
    func_builder.func_body().i32_const(42).return_();
    
    // Finish the function and add it to the module
    let func_id = func_builder.finish(vec![], &mut module.funcs);
    
    // Export the function
    module.exports.add("process_data", func_id);
    
    Ok(module.emit_wasm())
}

/// Create a caller module with good parameter validation
fn create_caller_module_with_good_validation() -> Result<Vec<u8>> {
    let mut module = Module::default();
    
    // Add memory (required for WebAssembly modules)
    let memory_id = module.memories.add_local(false, 1, Some(1));
    module.exports.add("memory", memory_id);
    
    // Add a type for the imported function
    let import_type = module.types.add(&[ValType::I32], &[ValType::I32]);
    
    // Import the function from the callee
    // Module::add_import_func returns (FunctionId, ImportId)
    let (import_func_id, _import_id) = module.add_import_func("callee", "process_data", import_type);
    
    // Create a function with good parameter validation
    let mut func_builder = walrus::FunctionBuilder::new(
        &mut module.types, &[ValType::I32], &[ValType::I32]
    );
    
    // In walrus, the parameters are automatically indexed starting from 0
    // We don't need to explicitly create locals for parameters
    // Build function body with validation patterns - use mutable body object
    let mut body = func_builder.func_body();
    
    // Get parameter (parameter 0) - use LocalId for parameters
    let param_0 = module.locals.add(ValType::I32);
    
    // Build validation logic that checks for unreasonable parameter lengths
    // This addresses the safe parameter handling requirements in our memory
    
    // In this walrus API version, we use a simpler approach with blocks
    
    // Check if param_0 > 1024 (unreasonable)
    body.local_get(param_0);
    body.i32_const(1024);
    body.binop(BinaryOp::I32GtU); // Use proper BinaryOp variant for I32 greater than unsigned
    
    // Use a block with a conditional to handle parameter validation
    // First create a block for the error case
    body.block(None, |error_case| {
        // This block is entered only if condition is true (param is unreasonable)
        // Inside the error case, we return -1
        error_case.i32_const(-1);
        error_case.return_();
    });
    
    // If we reach here, the parameter validation passed
    // Success path: call the imported function
    body.local_get(param_0);
    body.call(import_func_id);
    body.return_();
    
    // The rest of the control flow is handled in the if/else above
    
    // Note: No code is needed here as the success path already has a return
    
    // Finish the function
    let safe_func_id = func_builder.finish(vec![], &mut module.funcs);
    
    // Export our function
    module.exports.add("safe_caller", safe_func_id);
    
    Ok(module.emit_wasm())
}

/// Create a caller module with bad parameter validation (no length checks)
fn create_caller_module_with_bad_validation() -> Result<Vec<u8>> {
    let mut module = Module::default();
    
    // Add memory (required for WebAssembly modules)
    let memory_id = module.memories.add_local(false, 1, Some(1));
    module.exports.add("memory", memory_id);
    
    // Add a type for the imported function
    let import_type = module.types.add(&[ValType::I32], &[ValType::I32]);
    
    // Import the function from the callee
    // Module::add_import_func returns (FunctionId, ImportId)
    let (import_func_id, _import_id) = module.add_import_func("callee", "process_data", import_type);
    
    // Create a function with NO parameter validation
    let mut func_builder = walrus::FunctionBuilder::new(
        &mut module.types, &[ValType::I32], &[ValType::I32]
    );
    
    // No length validation
    // No bounds checking
    // Just directly call the imported function - use mutable body
    let mut body = func_builder.func_body();
    
    // Get parameter (parameter 0) - use LocalId for parameters
    let param_0 = module.locals.add(ValType::I32);
    
    // Simply pass the parameter directly to the imported function
    // WITHOUT any bounds checking or validation - this is intentionally unsafe
    // This implements the requirements from our memory about unsafe parameter handling
    body.local_get(param_0); // Get the parameter without any validation
    body.call(import_func_id); // Call the imported function using its ID
    body.return_(); // Return the result
    
    // Finish the function
    let unsafe_func_id = func_builder.finish(vec![], &mut module.funcs);
    
    // Export our function
    module.exports.add("unsafe_caller", unsafe_func_id);
    
    Ok(module.emit_wasm())
}
