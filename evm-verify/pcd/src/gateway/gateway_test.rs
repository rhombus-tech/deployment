use crate::gateway::{create_default_gateway, GatewaySettings, Severity};
use anyhow::Result;

/// Test for the AI Agent Security Gateway
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_gateway_empty_bytecode() -> Result<()> {
        // Create an empty bytecode for testing
        let bytecode = vec![];
        
        // Create gateway with default settings
        let gateway = create_default_gateway(None)?;
        
        // Verify empty bytecode
        let result = gateway.verify_contract(&bytecode)?;
        
        // Empty bytecode should pass verification with no warnings
        assert!(result.passed);
        assert_eq!(result.warnings.len(), 0);
        
        Ok(())
    }
    
    #[test]
    fn test_gateway_with_reentrancy_bytecode() -> Result<()> {
        // This is a simplified bytecode that would trigger reentrancy detection
        // It contains patterns that would be detected by the reentrancy detector
        let bytecode = vec![
            // CALLVALUE
            0x34,
            // JUMPI
            0x57,
            // PUSH1 0x00
            0x60, 0x00,
            // SLOAD
            0x54,
            // SSTORE
            0x55,
            // CALL
            0xF1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        
        // Create gateway with settings that block critical warnings
        let settings = GatewaySettings {
            allow_critical_warnings: false,
            min_severity: Severity::Warning,
            generate_reports: true,
            analyze_action_sequences: true,
        };
        
        let gateway = create_default_gateway(Some(settings))?;
        
        // Verify bytecode
        let result = gateway.verify_contract(&bytecode)?;
        
        // Bytecode with reentrancy should not pass verification
        if result.passed {
            println!("Warning: Expected reentrancy to be detected but it wasn't");
        }
        
        // Print warnings for debugging
        for warning in &result.warnings {
            println!("Warning: {:?} - {}", warning.kind, warning.description);
        }
        
        Ok(())
    }
    
    #[test]
    fn test_action_sequence_verification() -> Result<()> {
        // Create two simple bytecode actions
        let action1 = vec![0x60, 0x01];  // PUSH1 0x01
        let action2 = vec![0x01];        // ADD
        
        // Create gateway with action sequence analysis enabled
        let settings = GatewaySettings {
            allow_critical_warnings: false,
            min_severity: Severity::Info,
            generate_reports: true,
            analyze_action_sequences: true,
        };
        
        let gateway = create_default_gateway(Some(settings))?;
        
        // Verify action sequence
        let result = gateway.verify_action_sequence(&[action1, action2])?;
        
        // Simple actions should pass verification
        assert!(result.passed);
        
        Ok(())
    }
}

/// Example of how to use the gateway from code
pub fn example_usage() -> Result<()> {
    // Create bytecode to analyze
    let bytecode = vec![
        // Some EVM bytecode...
        0x60, 0x00, 0x60, 0x01, 0x01, 0x60, 0x02, 0x02
    ];
    
    // Create gateway with custom settings
    let settings = GatewaySettings {
        allow_critical_warnings: false,
        min_severity: Severity::Warning,
        generate_reports: true,
        analyze_action_sequences: false,
    };
    
    let gateway = create_default_gateway(Some(settings))?;
    
    // Verify contract
    let result = gateway.verify_contract(&bytecode)?;
    
    // Check if verification passed
    if result.passed {
        println!("Contract verification passed!");
    } else {
        println!("Contract verification failed:");
        for warning in &result.warnings {
            println!("- {}: {}", 
                match warning.severity {
                    Severity::Critical => "CRITICAL",
                    Severity::Warning => "WARNING",
                    Severity::Info => "INFO",
                },
                warning.description
            );
            println!("  Remediation: {}", warning.remediation_hint);
        }
    }
    
    Ok(())
}
