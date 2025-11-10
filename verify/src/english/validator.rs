// Validator for English contracts
use super::EnglishContract;
use anyhow::{Context, Result};

pub struct ContractValidator;

impl ContractValidator {
    pub fn new() -> Self {
        Self
    }
    
    pub fn validate(&self, contract: &EnglishContract) -> Result<ValidationResult> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        
        // Validate contract name
        if contract.name.is_empty() {
            errors.push("Contract name is required".to_string());
        }
        
        // Validate functions exist
        if contract.functions.is_empty() {
            errors.push("Contract must have at least one function".to_string());
        }
        
        // Validate each function
        for func in &contract.functions {
            if func.name.is_empty() {
                errors.push("Function missing name".to_string());
            }
            
            if func.requirements.is_empty() {
                warnings.push(format!("Function '{}' has no security requirements", func.name));
            }
            
            // Check for dangerous patterns
            for step in &func.steps {
                let step_lower = step.to_lowercase();
                if step_lower.contains("transfer all") {
                    warnings.push(format!("Function '{}' contains 'transfer all' - potential drain risk", func.name));
                }
                if step_lower.contains("delete") || step_lower.contains("destroy") {
                    warnings.push(format!("Function '{}' contains destructive operation", func.name));
                }
            }
        }
        
        // Check for reentrancy risks
        self.check_reentrancy(&contract.functions, &mut warnings);
        
        // Check for access control
        self.check_access_control(&contract.functions, &mut warnings);
        
        if !errors.is_empty() {
            anyhow::bail!("Validation errors: {:?}", errors);
        }
        
        Ok(ValidationResult {
            valid: errors.is_empty(),
            errors,
            warnings,
        })
    }
    
    fn check_reentrancy(&self, functions: &[super::ContractFunction], warnings: &mut Vec<String>) {
        for func in functions {
            let has_external_call = func.steps.iter().any(|s| {
                s.to_lowercase().contains("call") || 
                s.to_lowercase().contains("transfer")
            });
            
            let has_state_change = func.steps.iter().any(|s| {
                s.to_lowercase().contains("set") || 
                s.to_lowercase().contains("update") ||
                s.to_lowercase().contains("modify")
            });
            
            if has_external_call && has_state_change {
                warnings.push(format!(
                    "Function '{}' may be vulnerable to reentrancy (external call + state change)",
                    func.name
                ));
            }
        }
    }
    
    fn check_access_control(&self, functions: &[super::ContractFunction], warnings: &mut Vec<String>) {
        for func in functions {
            let is_privileged = func.steps.iter().any(|s| {
                s.to_lowercase().contains("mint") ||
                s.to_lowercase().contains("burn") ||
                s.to_lowercase().contains("admin") ||
                s.to_lowercase().contains("owner")
            });
            
            let has_auth_check = func.requirements.iter().any(|r| {
                r.to_lowercase().contains("owner") ||
                r.to_lowercase().contains("admin") ||
                r.to_lowercase().contains("authorized")
            });
            
            if is_privileged && !has_auth_check {
                warnings.push(format!(
                    "Function '{}' performs privileged operation without access control",
                    func.name
                ));
            }
        }
    }
}

#[derive(Debug)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::english::*;
    
    #[test]
    fn test_valid_contract() {
        let validator = ContractValidator::new();
        
        let contract = EnglishContract {
            name: "TestContract".to_string(),
            description: "Test".to_string(),
            config: Default::default(),
            state: vec![],
            functions: vec![ContractFunction {
                name: "transfer".to_string(),
                description: "".to_string(),
                parameters: vec![],
                returns: vec![],
                requirements: vec!["Sender must be authorized".to_string()],
                steps: vec!["Transfer tokens".to_string()],
                visibility: Visibility::Public,
            }],
            events: vec![],
        };
        
        let result = validator.validate(&contract).unwrap();
        assert!(result.valid);
    }
    
    #[test]
    fn test_empty_name() {
        let validator = ContractValidator::new();
        
        let contract = EnglishContract {
            name: "".to_string(),
            description: "Test".to_string(),
            config: Default::default(),
            state: vec![],
            functions: vec![],
            events: vec![],
        };
        
        assert!(validator.validate(&contract).is_err());
    }
}
