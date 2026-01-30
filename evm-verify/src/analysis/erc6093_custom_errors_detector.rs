/// ERC-6093 Custom Errors Detector
///
/// Detects vulnerabilities in ERC-6093 custom error implementations for
/// ERC20, ERC721, and ERC1155 tokens.
///
/// Standard: ERC-6093 (Final, 2024)
/// Impact: Standardized error handling, missing error checks
/// Coverage: Custom errors vs revert strings

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc6093Vulnerability {
    pub vulnerability_type: Erc6093VulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc6093VulnerabilityType {
    MissingCustomErrors,            // Uses revert strings instead of custom errors
    IncorrectErrorSelector,         // Wrong custom error selector
    MissingErrorParameter,          // Custom error missing required parameters
    ErrorInWrongContext,            // Error used in wrong context
    InsufficientBalanceNotUsed,     // ERC20InsufficientBalance not used
    InvalidReceiverNotUsed,         // ERC721InvalidReceiver not used
    InsufficientApprovalNotUsed,    // Insufficient approval error missing
    InvalidSenderNotUsed,           // ERC20InvalidSender not used
    InvalidSpenderNotUsed,          // ERC20InvalidSpender not used
    InvalidApproverNotUsed,         // ERC20Invalid Approver not used
}

pub struct Erc6093CustomErrorsDetector {
    bytecode: Vec<u8>,
}

impl Erc6093CustomErrorsDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Erc6093Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        vulnerabilities.extend(self.detect_missing_custom_errors());
        vulnerabilities.extend(self.detect_incorrect_error_usage());
        
        vulnerabilities
    }
    
    fn detect_missing_custom_errors(&self) -> Vec<Erc6093Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // ERC-6093 defines specific custom error selectors
        let erc20_insufficient_balance = [0xe4, 0x50, 0xd3, 0x8c]; // ERC20InsufficientBalance
        let erc20_invalid_sender = [0x96, 0xc6, 0xfd, 0x1e]; // ERC20InvalidSender
        let erc721_invalid_receiver = [0x64, 0xa0, 0x39, 0x25]; // ERC721InvalidReceiver
        
        let has_erc20_insufficient = self.bytecode.windows(4).any(|w| w == erc20_insufficient_balance);
        let has_erc20_invalid_sender = self.bytecode.windows(4).any(|w| w == erc20_invalid_sender);
        
        // Check for transfer logic without custom errors
        for i in 0..self.bytecode.len().saturating_sub(20) {
            let mut has_transfer = false;
            let mut has_revert = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                // Transfer (balance update)
                if self.bytecode[j] == 0x03 && // SUB
                   j + 1 < self.bytecode.len() && self.bytecode[j+1] == 0x55 { // SSTORE
                    has_transfer = true;
                }
                // Old-style revert
                if self.bytecode[j] == 0xFD { // REVERT
                    has_revert = true;
                }
            }
            
            if has_transfer && has_revert && !has_erc20_insufficient {
                vulnerabilities.push(Erc6093Vulnerability {
                    vulnerability_type: Erc6093VulnerabilityType::MissingCustomErrors,
                    severity: "Low".to_string(),
                    location: vec![i],
                    description: "Token uses revert strings instead of ERC-6093 standardized \
                                custom errors. Not compliant with modern error standard.".to_string(),
                    exploit_scenario: "1. Token implements ERC20 with old revert strings\n\
                                      2. Frontend calls transfer with insufficient balance\n\
                                      3. Gets generic revert string 'Insufficient balance'\n\
                                      4. Cannot programmatically detect exact error type\n\
                                      5. UX degraded - can't show specific error messages\n\
                                      6. Integrations break - expect custom errors\n\
                                      7. Not compliant with ERC-6093 standard\n\
                                      8. Higher gas costs (strings vs custom errors)".to_string(),
                    recommendation: "Implement ERC-6093 custom errors:\n\
                                  error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed);\n\
                                  error ERC20InvalidSender(address sender);\n\
                                  error ERC20InvalidReceiver(address receiver);\n\
                                  Use these instead of revert strings. Reference: ERC-6093 specification.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
    
    fn detect_incorrect_error_usage(&self) -> Vec<Erc6093Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern: Custom error with wrong number of parameters
        for i in 0..self.bytecode.len().saturating_sub(30) {
            let mut has_error_selector = false;
            let mut param_count = 0;
            
            for j in i..self.bytecode.len().min(i + 30) {
                // Error selector (first 4 bytes)
                if self.bytecode[j] == 0x08 && // INVALID opcode (error marker)
                   j + 4 < self.bytecode.len() {
                    has_error_selector = true;
                }
                // Count parameters (MSTORE operations before revert)
                if self.bytecode[j] == 0x52 { // MSTORE
                    param_count += 1;
                }
            }
            
            // ERC20InsufficientBalance should have 3 parameters
            if has_error_selector && param_count < 3 {
                vulnerabilities.push(Erc6093Vulnerability {
                    vulnerability_type: Erc6093VulnerabilityType::MissingErrorParameter,
                    severity: "Medium".to_string(),
                    location: vec![i],
                    description: "Custom error missing required parameters per ERC-6093 specification.".to_string(),
                    exploit_scenario: "1. Contract emits ERC20InsufficientBalance error\n\
                                      2. But only includes sender address\n\
                                      3. Missing balance and needed amount\n\
                                      4. Frontend can't tell user how much they're short\n\
                                      5. Poor UX - user sees 'insufficient balance' with no details\n\
                                      6. Not compliant with ERC-6093\n\
                                      7. Breaking integrations expecting full error data".to_string(),
                    recommendation: "Include all required parameters in custom errors:\n\
                                  ERC20InsufficientBalance(sender, currentBalance, amountNeeded)\n\
                                  ERC721InvalidReceiver(receiver)\n\
                                  Follow ERC-6093 specification exactly.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_missing_custom_errors() {
        let bytecode = vec![
            0x03, // SUB (transfer)
            0x55, // SSTORE
            0xFD, // REVERT (old style)
        ];
        
        let detector = Erc6093CustomErrorsDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            Erc6093VulnerabilityType::MissingCustomErrors
        )));
    }
}
