use anyhow::Result;
use ark_ff::Field;
use std::collections::{HashMap, HashSet};

/// Data structure representing import data
pub struct ImportData {
    /// Module name
    pub module_name: String,
    /// Import name
    pub name: String,
    /// Type index for function signature
    pub type_idx: u32,
}

/// Data structure representing parameter validation
pub struct ParameterValidation {
    /// Function index
    pub function_idx: u32,
    /// Has length validation
    pub validates_length: bool,
    /// Has bounds validation
    pub validates_bounds: bool,
    /// Has reasonable length limit check
    pub validates_reasonable_length: bool,
    /// Returns safely on error (vs panicking)
    pub safe_error_handling: bool,
}

/// Circuit for validating cross-module interactions
pub struct ModuleInteractionCircuit<F: Field> {
    /// Phantom data for the field
    _field: std::marker::PhantomData<F>,
    /// Imported functions
    imports: Vec<ImportData>,
    /// Known modules for validation
    known_modules: HashSet<String>,
    /// Parameter validations by exported functions
    parameter_validations: HashMap<u32, ParameterValidation>,
    /// Maximum reasonable parameter length in bytes
    max_reasonable_param_length: u32,
    /// Dependencies between modules (module_name -> dependencies)
    module_dependencies: HashMap<String, HashSet<String>>,
}

impl<F: Field> ModuleInteractionCircuit<F> {
    /// Create a new module interaction circuit
    pub fn new(
        imports: Vec<ImportData>,
        known_modules: HashSet<String>,
        parameter_validations: HashMap<u32, ParameterValidation>,
        max_reasonable_param_length: u32,
    ) -> Self {
        // Initialize empty module dependencies
        let module_dependencies = HashMap::new();
        
        Self {
            _field: std::marker::PhantomData,
            imports,
            known_modules,
            parameter_validations,
            max_reasonable_param_length,
            module_dependencies,
        }
    }
    
    /// Analyze import dependencies to construct the dependency graph
    pub fn analyze_dependencies(&mut self) {
        // Clear existing dependencies
        self.module_dependencies.clear();
        
        // Process each import
        for import in &self.imports {
            // Get or create dependencies for the importing module
            let deps = self.module_dependencies
                .entry("current_module".to_string()) // This should be the current module name
                .or_insert_with(HashSet::new);
                
            // Add the dependency
            deps.insert(import.module_name.clone());
        }
    }
    
    /// Check for circular dependencies
    pub fn validate_no_circular_dependencies(&self) -> Result<()> {
        // Start with empty visited and recursion sets
        let mut visited = HashSet::new();
        let mut recursion_stack = HashSet::new();
        
        // Check each module in the dependency graph
        for module in self.module_dependencies.keys() {
            if !visited.contains(module) {
                if self.is_cyclic(module, &mut visited, &mut recursion_stack) {
                    return Err(anyhow::anyhow!("Circular dependency detected involving module: {}", module));
                }
            }
        }
        
        Ok(())
    }
    
    /// Helper for cycle detection using DFS
    fn is_cyclic(
        &self, 
        module: &str, 
        visited: &mut HashSet<String>, 
        recursion_stack: &mut HashSet<String>
    ) -> bool {
        // Mark current node as visited and add to recursion stack
        visited.insert(module.to_string());
        recursion_stack.insert(module.to_string());
        
        // If this module has dependencies, check them
        if let Some(deps) = self.module_dependencies.get(module) {
            for dep in deps {
                // If not visited, perform recursive check
                if !visited.contains(dep) {
                    if self.is_cyclic(dep, visited, recursion_stack) {
                        return true;
                    }
                } 
                // If in recursion stack, we have a cycle
                else if recursion_stack.contains(dep) {
                    return true;
                }
            }
        }
        
        // Remove from recursion stack
        recursion_stack.remove(module);
        false
    }
    
    /// Validate that all imports come from known modules
    pub fn validate_known_imports(&self) -> Result<()> {
        for import in &self.imports {
            if !self.known_modules.contains(&import.module_name) {
                return Err(anyhow::anyhow!(
                    "Import from unknown module: {}.{}", 
                    import.module_name, 
                    import.name
                ));
            }
        }
        Ok(())
    }
    
    /// Validate parameter handling for all functions that handle parameters
    pub fn validate_parameter_handling(&self) -> Result<()> {
        for (func_idx, validation) in &self.parameter_validations {
            // Check if this function validates length
            if !validation.validates_length {
                return Err(anyhow::anyhow!(
                    "Function {} does not validate parameter length", 
                    func_idx
                ));
            }
            
            // Check if this function validates bounds
            if !validation.validates_bounds {
                return Err(anyhow::anyhow!(
                    "Function {} does not validate parameter bounds", 
                    func_idx
                ));
            }
            
            // Check if this function validates reasonable length
            if !validation.validates_reasonable_length {
                return Err(anyhow::anyhow!(
                    "Function {} does not check for reasonable parameter length", 
                    func_idx
                ));
            }
            
            // Check for safe error handling
            if !validation.safe_error_handling {
                return Err(anyhow::anyhow!(
                    "Function {} may panic on invalid parameters", 
                    func_idx
                ));
            }
        }
        
        Ok(())
    }
    
    /// Validate that parameters are checked against reasonable maximum lengths
    pub fn validate_reasonable_parameter_lengths(&self) -> Result<()> {
        for (func_idx, validation) in &self.parameter_validations {
            // Skip functions that don't handle parameters
            if !validation.validates_length {
                continue;
            }
            
            // For those that do, check if they enforce reasonable limits
            if !validation.validates_reasonable_length {
                return Err(anyhow::anyhow!(
                    "Function {} allows unreasonably large parameters (should be limited to {} bytes)",
                    func_idx,
                    self.max_reasonable_param_length
                ));
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    
    #[test]
    fn test_circular_dependency_detection() -> Result<()> {
        // Create circuit with some imports
        let mut circuit = ModuleInteractionCircuit::<Fr>::new(
            vec![
                ImportData {
                    module_name: "module_a".to_string(),
                    name: "func1".to_string(),
                    type_idx: 1,
                },
                ImportData {
                    module_name: "module_b".to_string(),
                    name: "func2".to_string(),
                    type_idx: 2,
                },
            ],
            vec!["module_a".to_string(), "module_b".to_string(), "module_c".to_string()]
                .into_iter()
                .collect(),
            HashMap::new(),
            1024,
        );
        
        // Manually set up a dependency graph with no cycles
        circuit.module_dependencies.insert(
            "current_module".to_string(),
            vec!["module_a".to_string(), "module_b".to_string()].into_iter().collect(),
        );
        circuit.module_dependencies.insert(
            "module_a".to_string(),
            vec!["module_c".to_string()].into_iter().collect(),
        );
        circuit.module_dependencies.insert(
            "module_b".to_string(),
            vec!["module_c".to_string()].into_iter().collect(),
        );
        circuit.module_dependencies.insert("module_c".to_string(), HashSet::new());
        
        // This should pass as there are no cycles
        assert!(circuit.validate_no_circular_dependencies().is_ok());
        
        // Now introduce a cycle
        circuit.module_dependencies.get_mut("module_c").unwrap()
            .insert("current_module".to_string());
            
        // This should fail due to the cycle
        assert!(circuit.validate_no_circular_dependencies().is_err());
        
        Ok(())
    }
    
    #[test]
    fn test_parameter_validation() -> Result<()> {
        // Create circuit with parameter validations
        let mut validations = HashMap::new();
        
        // Add a good function
        validations.insert(1, ParameterValidation {
            function_idx: 1,
            validates_length: true,
            validates_bounds: true,
            validates_reasonable_length: true,
            safe_error_handling: true,
        });
        
        // Add a bad function that doesn't validate length
        validations.insert(2, ParameterValidation {
            function_idx: 2,
            validates_length: false,
            validates_bounds: true,
            validates_reasonable_length: true,
            safe_error_handling: true,
        });
        
        let circuit = ModuleInteractionCircuit::<Fr>::new(
            vec![],
            HashSet::new(),
            validations,
            1024,
        );
        
        // Should fail because function 2 doesn't validate length
        assert!(circuit.validate_parameter_handling().is_err());
        
        // Create circuit with only good validations
        let mut good_validations = HashMap::new();
        good_validations.insert(1, ParameterValidation {
            function_idx: 1,
            validates_length: true,
            validates_bounds: true,
            validates_reasonable_length: true,
            safe_error_handling: true,
        });
        
        let good_circuit = ModuleInteractionCircuit::<Fr>::new(
            vec![],
            HashSet::new(),
            good_validations,
            1024,
        );
        
        // Should pass with all good validations
        assert!(good_circuit.validate_parameter_handling().is_ok());
        
        Ok(())
    }
}
