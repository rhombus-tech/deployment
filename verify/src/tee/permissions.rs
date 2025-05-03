use anyhow::{Result, anyhow};
use std::collections::{HashMap, HashSet};
use walrus::{Module, ImportId, FunctionId};

/// Security level for host functions
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// Safe function that can be called without restrictions
    Safe,
    /// Function that requires special permissions, but doesn't affect determinism
    Restricted,
    /// Function that could affect determinism and requires explicit approval
    Sensitive,
    /// Function that is not allowed in TEE context
    Forbidden,
}

/// Host function category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FunctionCategory {
    /// Time-related functions (clock, timers)
    Time,
    /// Random number generation
    Random,
    /// Hardware access (SIMD, platform-specific)
    Hardware,
    /// Storage or state access
    Storage,
    /// Network or external communication
    Network,
    /// Cryptographic operations
    Crypto,
    /// Console or logging operations
    Logging,
    /// Environment access (env vars, args)
    Environment,
    /// Misc/Other functions
    Other,
}

/// Permission registry for host functions
#[derive(Debug, Clone)]
pub struct HostFunctionRegistry {
    /// Maps module.name to its security level and category
    permissions: HashMap<String, HashMap<String, (SecurityLevel, FunctionCategory)>>,
    /// Default security level for unknown functions
    default_level: SecurityLevel,
    /// Module permissions
    module_permissions: HashSet<FunctionCategory>,
}

impl HostFunctionRegistry {
    /// Create a new host function registry with default permissions
    pub fn new() -> Self {
        let mut registry = Self {
            permissions: HashMap::new(),
            default_level: SecurityLevel::Forbidden,
            module_permissions: HashSet::new(),
        };

        // Register standard permissions
        registry.register_standard_permissions();
        registry
    }

    /// Register standard permissions for common modules
    fn register_standard_permissions(&mut self) {
        // Environment functions
        let mut env_funcs = HashMap::new();
        env_funcs.insert("memory".to_string(), (SecurityLevel::Safe, FunctionCategory::Storage));
        env_funcs.insert("get_time".to_string(), (SecurityLevel::Sensitive, FunctionCategory::Time));
        env_funcs.insert("random".to_string(), (SecurityLevel::Sensitive, FunctionCategory::Random));
        env_funcs.insert("abort".to_string(), (SecurityLevel::Restricted, FunctionCategory::Other));
        env_funcs.insert("seed_random".to_string(), (SecurityLevel::Forbidden, FunctionCategory::Random));
        self.permissions.insert("env".to_string(), env_funcs);

        // WASI functions (subset)
        let mut wasi_funcs = HashMap::new();
        wasi_funcs.insert("fd_write".to_string(), (SecurityLevel::Restricted, FunctionCategory::Logging));
        wasi_funcs.insert("fd_read".to_string(), (SecurityLevel::Sensitive, FunctionCategory::Network));
        wasi_funcs.insert("random_get".to_string(), (SecurityLevel::Sensitive, FunctionCategory::Random));
        wasi_funcs.insert("clock_time_get".to_string(), (SecurityLevel::Sensitive, FunctionCategory::Time));
        self.permissions.insert("wasi_snapshot_preview1".to_string(), wasi_funcs);
    }

    /// Register a custom host function with its security level and category
    pub fn register_function(&mut self, module: &str, name: &str, level: SecurityLevel, category: FunctionCategory) {
        self.permissions
            .entry(module.to_string())
            .or_insert_with(HashMap::new)
            .insert(name.to_string(), (level, category));
    }

    /// Get the security level and category for a host function
    pub fn get_function_security(&self, module: &str, name: &str) -> (SecurityLevel, FunctionCategory) {
        if let Some(module_funcs) = self.permissions.get(module) {
            if let Some(&security) = module_funcs.get(name) {
                return security;
            }
        }
        (self.default_level, FunctionCategory::Other)
    }

    /// Set permissions for a module
    pub fn set_module_permissions(&mut self, categories: &[FunctionCategory]) {
        self.module_permissions.clear();
        self.module_permissions.extend(categories.iter().copied());
    }

    /// Check if a function is allowed with current permissions
    pub fn is_function_allowed(&self, module: &str, name: &str) -> bool {
        let (level, category) = self.get_function_security(module, name);
        
        if level == SecurityLevel::Forbidden {
            return false;
        }
        
        if level == SecurityLevel::Safe {
            return true;
        }
        
        self.module_permissions.contains(&category)
    }

    /// Validate all imports in a module
    pub fn validate_module_imports(&self, module: &Module) -> Result<HashMap<ImportId, (SecurityLevel, FunctionCategory)>> {
        let mut import_security = HashMap::new();

        // Check each imported function
        for import in module.imports.iter() {
            if let walrus::ImportKind::Function(_) = import.kind {
                let module_name = import.module.as_str();
                let field_name = import.name.as_str();
                
                let (level, category) = self.get_function_security(module_name, field_name);
                
                if level == SecurityLevel::Forbidden {
                    return Err(anyhow!(
                        "Module imports forbidden function: {}.{}", 
                        module_name, field_name
                    ));
                }
                
                if level != SecurityLevel::Safe && !self.module_permissions.contains(&category) {
                    return Err(anyhow!(
                        "Module imports function {}.{} without required permission for category {:?}",
                        module_name, field_name, category
                    ));
                }
                
                import_security.insert(import.id(), (level, category));
            }
        }
        
        Ok(import_security)
    }

    /// Get all non-deterministic imports from the module
    pub fn get_non_deterministic_imports(&self, module: &Module) -> Vec<(String, String, FunctionCategory)> {
        let mut non_deterministic = Vec::new();
        
        for import in module.imports.iter() {
            if let walrus::ImportKind::Function(_) = import.kind {
                let module_name = import.module.clone();
                let name = import.name.clone();
                
                // Get security level and category for this function
                let (level, category) = self.get_function_security(&module_name, &name);
                
                // Add non-deterministic imports to result
                if level == SecurityLevel::Restricted || level == SecurityLevel::Sensitive {
                    non_deterministic.push((module_name, name, category));
                }
            }
        }
        
        non_deterministic
    }
}

/// Host function permission validator
#[derive(Debug)]
pub struct HostFunctionValidator {
    registry: HostFunctionRegistry,
}

impl HostFunctionValidator {
    /// Create a new validator with default permissions
    pub fn new() -> Self {
        Self {
            registry: HostFunctionRegistry::new(),
        }
    }
    
    /// Create a new validator with custom permissions
    pub fn with_registry(registry: HostFunctionRegistry) -> Self {
        Self { registry }
    }
    
    /// Set permissions for a module
    pub fn set_permissions(&mut self, categories: &[FunctionCategory]) {
        self.registry.set_module_permissions(categories);
    }

    /// Validate a module's imports
    pub fn validate(&self, module: &Module) -> Result<Vec<(String, String, FunctionCategory)>> {
        // Check all imports against permissions
        // This call will return an error if any forbidden imports are found
        self.registry.validate_module_imports(module)?;
        
        // Identify non-deterministic imports (these are allowed but potentially unsafe)
        let non_deterministic = self.registry.get_non_deterministic_imports(module);
        
        Ok(non_deterministic)
    }
    
    /// Register a custom function
    pub fn register_function(&mut self, module: &str, name: &str, level: SecurityLevel, category: FunctionCategory) {
        self.registry.register_function(module, name, level, category);
    }
    
    /// Check if a specific import is allowed
    pub fn is_import_allowed(&self, module: &str, name: &str) -> bool {
        self.registry.is_function_allowed(module, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wat::parse_str;

    #[test]
    fn test_registry_defaults() {
        let registry = HostFunctionRegistry::new();
        
        // Test env.get_time (should be sensitive)
        let (level, category) = registry.get_function_security("env", "get_time");
        assert_eq!(level, SecurityLevel::Sensitive);
        assert_eq!(category, FunctionCategory::Time);
        
        // Test unknown function (should be forbidden)
        let (level, _) = registry.get_function_security("unknown", "function");
        assert_eq!(level, SecurityLevel::Forbidden);
    }
    
    #[test]
    fn test_register_custom_function() {
        let mut registry = HostFunctionRegistry::new();
        
        // Register custom function
        registry.register_function(
            "custom", 
            "my_function", 
            SecurityLevel::Restricted, 
            FunctionCategory::Crypto
        );
        
        // Verify registration
        let (level, category) = registry.get_function_security("custom", "my_function");
        assert_eq!(level, SecurityLevel::Restricted);
        assert_eq!(category, FunctionCategory::Crypto);
    }
    
    #[test]
    fn test_validate_allowed_imports() -> Result<()> {
        let wat = r#"
            (module
                (import "env" "memory" (memory 1))
                (import "env" "abort" (func $abort (param i32 i32 i32 i32)))
                (func $start)
                (export "start" (func $start))
            )
        "#;
        
        let wasm = parse_str(wat)?;
        let module = Module::from_buffer(&wasm)?;
        
        let mut validator = HostFunctionValidator::new();
        validator.set_permissions(&[FunctionCategory::Other]); // Allow "Other" category for abort
        
        // Should validate successfully since all imports are allowed
        validator.validate(&module)?;
        
        Ok(())
    }

    #[test]
    fn test_validate_forbidden_imports() -> Result<()> {
        let wat = r#"
            (module
                (import "env" "memory" (memory 1))
                (import "env" "seed_random" (func $seed (param i32)))
                (func $start)
                (export "start" (func $start))
            )
        "#;
        
        let wasm = parse_str(wat)?;
        let module = Module::from_buffer(&wasm)?;
        
        let validator = HostFunctionValidator::new();
        
        // Should fail validation due to forbidden seed_random
        assert!(validator.validate(&module).is_err());
        
        Ok(())
    }
    
    #[test]
    fn test_validate_sensitive_imports() -> Result<()> {
        let wat = r#"
            (module
                (import "env" "memory" (memory 1))
                (import "env" "get_time" (func $time (result i64)))
                (func $start (result i64)
                    call $time
                )
                (export "start" (func $start))
            )
        "#;
        
        let wasm = parse_str(wat)?;
        let module = Module::from_buffer(&wasm)?;
        
        let mut validator = HostFunctionValidator::new();
        
        // Should identify the non-deterministic import, but validation passes when Time category is allowed
        validator.set_permissions(&[FunctionCategory::Time]);
        let non_deterministic = validator.validate(&module)?;
        
        assert_eq!(non_deterministic.len(), 1);
        assert_eq!(non_deterministic[0].0, "env");
        assert_eq!(non_deterministic[0].1, "get_time");
        assert_eq!(non_deterministic[0].2, FunctionCategory::Time);
        
        Ok(())
    }
}
