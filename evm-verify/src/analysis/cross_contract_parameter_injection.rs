/// Cross-Contract Parameter Injection Detector
///
/// Detects vulnerabilities where unvalidated parameters from one protocol
/// are passed to another protocol without proper sanitization/validation.
///
/// Examples:
/// - DeltaPrime: Malicious collateral address parameter cascaded to Aave
/// - Euler Finance: Manipulated liquidation parameters
/// - Cross-protocol slippage parameter injection
/// - Unvalidated deadline/expiry parameters
///
/// Real exploits: DeltaPrime ($4.8M), Euler Finance ($197M)

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractParameterInjectionVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub parameter_type: ParameterType,
    pub injection_vector: InjectionVector,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ParameterType {
    /// Address parameters (token, collateral, etc.)
    Address,
    /// Amount/value parameters
    Amount,
    /// Deadline/timestamp parameters
    Deadline,
    /// Slippage/tolerance parameters
    Slippage,
    /// Oracle price parameters
    PriceData,
    /// Calldata/function selector
    Calldata,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InjectionVector {
    /// Direct passthrough without validation
    DirectPassthrough,
    /// User-controlled parameter to external call
    UserControlled,
    /// Unvalidated oracle data
    OracleData,
    /// Delegated parameter from untrusted source
    DelegatedParameter,
    /// Array/batch parameter injection
    BatchInjection,
}

pub struct CrossContractParameterInjectionAnalyzer;

impl CrossContractParameterInjectionAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractParameterInjectionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for direct parameter passthrough
        if self.has_unvalidated_passthrough(bytecode) {
            vulnerabilities.push(CrossContractParameterInjectionVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Parameters passed directly to external call without validation".to_string(),
                location: "External call preparation".to_string(),
                parameter_type: ParameterType::Address,
                injection_vector: InjectionVector::DirectPassthrough,
                impact: "Attacker can inject malicious addresses/values into external protocol calls".to_string(),
            });
        }

        // Check for user-controlled external parameters
        if self.has_user_controlled_external_param(bytecode) {
            vulnerabilities.push(CrossContractParameterInjectionVulnerability {
                severity: SecuritySeverity::Critical,
                description: "User-controlled input used in external protocol call".to_string(),
                location: "User input handling".to_string(),
                parameter_type: ParameterType::Calldata,
                injection_vector: InjectionVector::UserControlled,
                impact: "User can control parameters passed to external protocols, enabling exploitation".to_string(),
            });
        }

        // Check for unvalidated amount parameters
        if self.has_unvalidated_amount_param(bytecode) {
            vulnerabilities.push(CrossContractParameterInjectionVulnerability {
                severity: SecuritySeverity::High,
                description: "Amount parameters passed to external calls without bounds checking".to_string(),
                location: "Amount parameter handling".to_string(),
                parameter_type: ParameterType::Amount,
                injection_vector: InjectionVector::DirectPassthrough,
                impact: "Extreme values can break external protocol assumptions".to_string(),
            });
        }

        // Check for deadline/expiry injection
        if self.has_deadline_injection(bytecode) {
            vulnerabilities.push(CrossContractParameterInjectionVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Deadline parameter not validated before external call".to_string(),
                location: "Deadline handling".to_string(),
                parameter_type: ParameterType::Deadline,
                injection_vector: InjectionVector::UserControlled,
                impact: "Manipulation of deadline can enable sandwich attacks or prevent transaction execution".to_string(),
            });
        }

        // Check for slippage parameter injection
        if self.has_slippage_injection(bytecode) {
            vulnerabilities.push(CrossContractParameterInjectionVulnerability {
                severity: SecuritySeverity::High,
                description: "Slippage tolerance parameter passed without validation".to_string(),
                location: "Slippage parameter".to_string(),
                parameter_type: ParameterType::Slippage,
                injection_vector: InjectionVector::UserControlled,
                impact: "100% slippage tolerance can be injected, allowing complete value extraction".to_string(),
            });
        }

        // Check for batch/array parameter injection
        if self.has_batch_injection(bytecode) {
            vulnerabilities.push(CrossContractParameterInjectionVulnerability {
                severity: SecuritySeverity::High,
                description: "Batch parameters not validated before external calls".to_string(),
                location: "Batch processing".to_string(),
                parameter_type: ParameterType::Calldata,
                injection_vector: InjectionVector::BatchInjection,
                impact: "Malicious addresses/data can be injected into batch operations".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_unvalidated_passthrough(&self, bytecode: &[u8]) -> bool {
        // Look for: CALLDATALOAD -> no checks -> MSTORE -> CALL
        // Pattern indicates direct parameter passthrough
        bytecode.windows(30).any(|window| {
            let has_calldataload = window.contains(&0x35); // CALLDATALOAD
            let has_call = window.contains(&0xf1) || window.contains(&0xfa); // CALL/STATICCALL
            let has_mstore = window.contains(&0x52); // MSTORE
            let no_validation = !window.contains(&0x57) && // No JUMPI
                               !window.contains(&0x10) && // No LT
                               !window.contains(&0x11);   // No GT
            
            has_calldataload && has_mstore && has_call && no_validation
        })
    }

    fn has_user_controlled_external_param(&self, bytecode: &[u8]) -> bool {
        // Look for: CALLDATALOAD -> used in external call without sanitization
        let calldataload_positions: Vec<usize> = bytecode.iter()
            .enumerate()
            .filter(|(_, &op)| op == 0x35)
            .map(|(i, _)| i)
            .collect();

        let external_call_positions: Vec<usize> = bytecode.iter()
            .enumerate()
            .filter(|(_, &op)| op == 0xf1 || op == 0xfa)
            .map(|(i, _)| i)
            .collect();

        // Check if CALLDATALOAD is close to external call (within 50 bytes)
        calldataload_positions.iter().any(|&cdl_pos| {
            external_call_positions.iter().any(|&call_pos| {
                call_pos > cdl_pos && call_pos - cdl_pos < 50
            })
        })
    }

    fn has_unvalidated_amount_param(&self, bytecode: &[u8]) -> bool {
        // Look for: amount loading -> external call without bounds check
        // Pattern: CALLDATALOAD -> CALL without LT/GT/ISZERO checks
        bytecode.windows(40).any(|window| {
            window.contains(&0x35) && // CALLDATALOAD (amount)
            (window.contains(&0xf1) || window.contains(&0xfa)) && // External call
            !window.contains(&0x10) && // No LT check
            !window.contains(&0x11) && // No GT check
            !window.contains(&0x15)    // No ISZERO check
        })
    }

    fn has_deadline_injection(&self, bytecode: &[u8]) -> bool {
        // Look for external calls with deadline parameter (common in DEX interactions)
        // Swap signatures often have deadline as last parameter
        let swap_sigs = [
            &[0x38, 0xed, 0x17, 0x39][..], // swapExactTokensForTokens
            &[0x88, 0x03, 0xdb, 0xee][..], // swapTokensForExactTokens  
        ];

        swap_sigs.iter().any(|sig| {
            bytecode.windows(sig.len()).any(|w| w == *sig)
        }) && !bytecode.contains(&0x42) // Has swap sig but no TIMESTAMP validation
    }

    fn has_slippage_injection(&self, bytecode: &[u8]) -> bool {
        // Look for: external swap call with potential unvalidated minAmount parameter
        // Pattern: CALLDATALOAD for minAmount -> no validation -> external call
        bytecode.windows(50).any(|window| {
            window.contains(&0x35) && // CALLDATALOAD (likely minAmount)
            (window.contains(&0x38) || window.contains(&0x88)) && // Swap function sig bytes
            !window.contains(&0x10) && // No LT validation
            (window.contains(&0xf1) || window.contains(&0xfa)) // External call
        })
    }

    fn has_batch_injection(&self, bytecode: &[u8]) -> bool {
        // Look for: array/loop operations with external calls
        // Pattern: CALLDATALOAD in loop + external call + no element validation
        let has_loop = bytecode.contains(&0x56); // JUMP (loop structure)
        let has_calldataload = bytecode.contains(&0x35);
        let has_external_call = bytecode.contains(&0xf1) || bytecode.contains(&0xfa);
        
        has_loop && has_calldataload && has_external_call &&
        // Check for lack of address validation in loop
        !bytecode.windows(20).any(|w| {
            w.contains(&0x3b) // EXTCODESIZE (address validation)
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractParameterInjectionVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractParameterInjection,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!(
                "Cross-Contract Parameter Injection: {} - Impact: {}",
                vuln.description, vuln.impact
            ),
            operations: Vec::new(),
            remediation: format!("Review {} - Validate all parameters before passing to external protocols", vuln.location),
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unvalidated_passthrough() {
        let analyzer = CrossContractParameterInjectionAnalyzer::new();
        
        // Bytecode: CALLDATALOAD -> MSTORE -> CALL (no validation)
        let bytecode = vec![
            0x35, // CALLDATALOAD
            0x52, // MSTORE
            0xf1, // CALL
        ];
        
        let vulns = analyzer.analyze(&bytecode);
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| matches!(
            v.injection_vector,
            InjectionVector::DirectPassthrough
        )));
    }

    #[test]
    fn test_slippage_injection() {
        let analyzer = CrossContractParameterInjectionAnalyzer::new();
        
        // Bytecode with swap signature + CALLDATALOAD + no validation
        let bytecode = vec![
            0x38, 0xed, 0x17, 0x39, // swapExactTokensForTokens signature
            0x35,                     // CALLDATALOAD (minAmount parameter)
            0xf1,                     // CALL
        ];
        
        let vulns = analyzer.analyze(&bytecode);
        assert!(!vulns.is_empty());
    }
}
