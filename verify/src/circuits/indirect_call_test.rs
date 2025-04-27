use crate::circuits::control_flow::ControlFlowCircuit;
use crate::parser::types::{FunctionTableInfo, TableType, RefType, Limits};
use ark_bls12_381::Fr;
use std::collections::HashMap;
use anyhow::Result;

/// Test the function table and indirect call validation
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_table_validation() -> Result<()> {
        // Create a table type
        let element_type = RefType::Func;
        let limits = Limits::new(10, Some(20));
        let table_type = TableType::new(element_type, limits)?;
        
        // Create a function table
        let mut function_table = FunctionTableInfo::new(0, table_type, 10);
        
        // Initialize some functions in the table
        function_table.set_element(0, 10, 0)?; // Function 10 with type 0
        function_table.set_element(1, 11, 1)?; // Function 11 with type 1
        function_table.set_element(2, 12, 0)?; // Function 12 with type 0
        
        // Mark the table as initialized
        function_table.mark_initialized();
        
        // Validate the table
        function_table.validate()?;
        
        // Test accessing elements
        let func0 = function_table.get_element(0).unwrap();
        assert_eq!(func0.function_idx, 10);
        assert_eq!(func0.type_idx, 0);
        
        let func1 = function_table.get_element(1).unwrap();
        assert_eq!(func1.function_idx, 11);
        assert_eq!(func1.type_idx, 1);
        
        // Test out of bounds access
        assert!(function_table.get_element(20).is_none());
        
        // Test setting an out of bounds element
        assert!(function_table.set_element(15, 13, 2).is_err());
        
        Ok(())
    }
    
    #[test]
    fn test_indirect_call_validation() -> Result<()> {
        // Set up function tables and mappings for the control flow circuit
        let function_table_sizes = vec![5];
        let mut function_table_elements = HashMap::new();
        let mut function_types = HashMap::new();
        
        // Add some elements
        function_table_elements.insert((0, 0), 10); // Table 0, element 0 -> function 10
        function_table_elements.insert((0, 1), 11); // Table 0, element 1 -> function 11
        function_table_elements.insert((0, 2), 12); // Table 0, element 2 -> function 12
        
        // Set function types
        function_types.insert(10, 0); // Function 10 has type 0
        function_types.insert(11, 1); // Function 11 has type 1
        function_types.insert(12, 0); // Function 12 has type 0
        
        // Create a control flow circuit
        let mut circuit = ControlFlowCircuit::<Fr>::new(
            Default::default(), // Call graph
            15,                // Max call depth
            vec![],            // Expected edges
            vec![],            // Expected calls
            function_table_sizes.clone(),
            function_table_elements.clone(),
            function_types.clone(),
        );
        
        // Test valid indirect calls
        circuit.validate_indirect_call(0, 0, 0)?; // Valid: table 0, element 0, type 0
        circuit.validate_indirect_call(0, 1, 1)?; // Valid: table 0, element 1, type 1
        circuit.validate_indirect_call(0, 2, 0)?; // Valid: table 0, element 2, type 0
        
        // Test invalid table index
        assert!(circuit.validate_indirect_call(1, 0, 0).is_err());
        
        // Test invalid element index
        assert!(circuit.validate_indirect_call(0, 10, 0).is_err());
        
        // Test type mismatch
        assert!(circuit.validate_indirect_call(0, 1, 0).is_err()); // Element 1 has type 1, not 0
        assert!(circuit.validate_indirect_call(0, 0, 1).is_err()); // Element 0 has type 0, not 1
        
        // Make sure call depth tracking works
        // Keep calling
        
        // Test the max call depth error
        // First verify that call depth is properly tracked
        // At this point we already have a call depth of 3 from the previous validation calls
        
        // Need to make calls until we hit max_depth-1 (15)
        for _ in 0..12 {
            // Must use the valid table entries we set up
            circuit.validate_indirect_call(0, 0, 0)?; // Table 0, element 0 -> function 10, type 0
        }
        
        // Verify current depth is now max_depth (15)
        assert_eq!(circuit.current_depth, 15);
        
        // The next call should fail because current_depth is 15,
        // which equals max_depth (15), so the check (current_depth >= max_depth) would be true
        assert!(circuit.validate_indirect_call(0, 0, 0).is_err());
        
        // Create a new circuit with same configuration to test other validation cases
        // This avoids issues with manually resetting depths and call stacks
        let mut new_circuit = ControlFlowCircuit::<Fr>::new(
            Default::default(), 15, vec![], vec![], function_table_sizes.clone(), 
            function_table_elements.clone(), function_types.clone(),
        );
        
        // Test type mismatch error (function 11 has type 1, but we're passing type 0)
        assert!(new_circuit.validate_indirect_call(0, 1, 0).is_err());
        
        // Test correct type matching
        new_circuit.validate_indirect_call(0, 1, 1)?; // Table 0, element 1 -> function 11, type 1
        
        // Test out of bounds table
        assert!(new_circuit.validate_indirect_call(1, 0, 0).is_err());
        
        // Test out of bounds element
        assert!(new_circuit.validate_indirect_call(0, 10, 0).is_err());
        
        // Test non-existent table element
        assert!(new_circuit.validate_indirect_call(0, 3, 0).is_err()); // We only added elements 0, 1, 2
        
        // Test call depth reduction works correctly with the original circuit
        for _ in 0..5 {
            circuit.validate_return()?; // Remove calls from the stack
        }
        // Depth should now be 10
        assert_eq!(circuit.current_depth, 10);
        // Now we should be able to call again
        circuit.validate_indirect_call(0, 0, 0)?;
        
        Ok(())
    }
}
