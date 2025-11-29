/// Flash Mint Provider Exploits Detector (EIP-3156)
/// Detects vulnerabilities in contracts that PROVIDE flash loans (lenders),
/// not borrowers. Focuses on implementation bugs in flashLoan() and maxFlashLoan()
///
/// Famous: Multiple flash loan providers with fee bypass, reentrancy issues

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlashMintProviderVulnerability {
    pub vulnerability_type: FlashMintProviderIssue,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FlashMintProviderIssue {
    MissingFeeEnforcement,         // flashLoan() doesn't charge fees
    IncorrectMaxFlashLoan,         // maxFlashLoan() returns wrong value
    CallbackReentrancy,            // Reentrancy in onFlashLoan callback
    MissingCallbackValidation,     // Doesn't validate callback return value
    FeeBypass,                     // Fee can be circumvented
    BalanceCheckMissing,           // Doesn't verify repayment
    UnlimitedMinting,              // Can mint unlimited tokens
}

pub struct FlashMintProviderDetector {
    bytecode: Vec<u8>,
}

impl FlashMintProviderDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<FlashMintProviderVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if this is a flash loan provider (EIP-3156)
        if !self.is_flash_loan_provider() {
            return vulnerabilities;
        }

        // Pattern 1: Missing fee enforcement
        vulnerabilities.extend(self.detect_missing_fee_enforcement());

        // Pattern 2: Incorrect maxFlashLoan implementation
        vulnerabilities.extend(self.detect_incorrect_max_flash_loan());

        // Pattern 3: Callback reentrancy
        vulnerabilities.extend(self.detect_callback_reentrancy());

        // Pattern 4: Missing callback validation
        vulnerabilities.extend(self.detect_missing_callback_validation());

        vulnerabilities
    }

    fn is_flash_loan_provider(&self) -> bool {
        // EIP-3156 function selectors:
        // flashLoan(address,address,uint256,bytes): 0x5cffe9de
        // flashFee(address,uint256): 0xd9d98ce4
        // maxFlashLoan(address): 0x613255ab
        
        let flash_loan_sig = [0x5c, 0xff, 0xe9, 0xde];
        let max_flash_loan_sig = [0x61, 0x32, 0x55, 0xab];
        
        let has_flash_loan = self.bytecode.windows(4).any(|w| w == flash_loan_sig);
        let has_max_flash = self.bytecode.windows(4).any(|w| w == max_flash_loan_sig);
        
        has_flash_loan || has_max_flash
    }

    fn detect_missing_fee_enforcement(&self) -> Vec<FlashMintProviderVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(flash_loan_pc) = self.find_flash_loan_function() {
            // Check if there's fee calculation
            let has_fee_calc = self.has_fee_calculation(flash_loan_pc, 200);
            let has_fee_transfer = self.has_token_transfer_after(flash_loan_pc, 200);
            
            if !has_fee_calc || !has_fee_transfer {
                vulnerabilities.push(FlashMintProviderVulnerability {
                    vulnerability_type: FlashMintProviderIssue::MissingFeeEnforcement,
                    severity: SecuritySeverity::Critical,
                    confidence: 0.85,
                    description:
                        "flashLoan() implementation doesn't properly enforce fees. \
                        Borrowers may be able to borrow for free.".to_string(),
                    exploit_scenario:
                        "Flash Loan Fee Bypass:\n\
                         1. Attacker calls flashLoan() with max amount\n\
                         2. No fee is charged or enforced\n\
                         3. Attacker uses funds for free\n\
                         4. Returns exact borrowed amount\n\
                         5. Protocol loses fee revenue\n\n\
                         Fix: Implement flashFee() and enforce payment in flashLoan()".to_string(),
                    location: flash_loan_pc,
                });
            }
        }

        vulnerabilities
    }

    fn detect_incorrect_max_flash_loan(&self) -> Vec<FlashMintProviderVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(max_flash_pc) = self.find_max_flash_loan_function() {
            // Check if maxFlashLoan returns a reasonable value
            // Should check available liquidity, not just return type(uint256).max
            
            let returns_max_uint = self.returns_max_uint256(max_flash_pc, 50);
            
            if returns_max_uint {
                vulnerabilities.push(FlashMintProviderVulnerability {
                    vulnerability_type: FlashMintProviderIssue::IncorrectMaxFlashLoan,
                    severity: SecuritySeverity::High,
                    confidence: 0.75,
                    description:
                        "maxFlashLoan() returns type(uint256).max instead of actual available liquidity. \
                        Can lead to failed transactions or unexpected behavior.".to_string(),
                    exploit_scenario:
                        "Incorrect Liquidity Reporting:\n\
                         1. maxFlashLoan() returns MAX_UINT256\n\
                         2. Borrower requests that amount\n\
                         3. flashLoan() fails due to insufficient liquidity\n\
                         4. Poor UX, wasted gas\n\n\
                         Fix: Return actual available balance: balanceOf(this) or totalSupply - borrowed".to_string(),
                    location: max_flash_pc,
                });
            }
        }

        vulnerabilities
    }

    fn detect_callback_reentrancy(&self) -> Vec<FlashMintProviderVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(flash_loan_pc) = self.find_flash_loan_function() {
            // Look for callback (onFlashLoan) followed by state changes
            let has_callback = self.has_callback_call(flash_loan_pc, 150);
            
            if has_callback {
                let has_state_change_after_callback = self.has_state_change_after_callback(flash_loan_pc);
                let has_reentrancy_guard = self.has_reentrancy_guard(flash_loan_pc, 100);
                
                if has_state_change_after_callback && !has_reentrancy_guard {
                    vulnerabilities.push(FlashMintProviderVulnerability {
                        vulnerability_type: FlashMintProviderIssue::CallbackReentrancy,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.80,
                        description:
                            "flashLoan() calls onFlashLoan callback before updating state. \
                            Vulnerable to reentrancy during callback.".to_string(),
                        exploit_scenario:
                            "Flash Loan Reentrancy:\n\
                             1. Attacker calls flashLoan()\n\
                             2. Receives tokens, onFlashLoan() callback invoked\n\
                             3. During callback, attacker reenters flashLoan()\n\
                             4. Gets more tokens before first loan is settled\n\
                             5. Can drain the pool\n\n\
                             Fix: Checks-Effects-Interactions or ReentrancyGuard".to_string(),
                        location: flash_loan_pc,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_missing_callback_validation(&self) -> Vec<FlashMintProviderVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(flash_loan_pc) = self.find_flash_loan_function() {
            let has_callback = self.has_callback_call(flash_loan_pc, 150);
            
            if has_callback {
                // Check if return value from callback is validated
                let validates_return = self.validates_callback_return(flash_loan_pc, 200);
                
                if !validates_return {
                    vulnerabilities.push(FlashMintProviderVulnerability {
                        vulnerability_type: FlashMintProviderIssue::MissingCallbackValidation,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description:
                            "flashLoan() doesn't validate onFlashLoan() return value. \
                            Should verify keccak256('ERC3156FlashBorrower.onFlashLoan').".to_string(),
                        exploit_scenario:
                            "Weak Callback Validation:\n\
                             1. Borrower implements malicious onFlashLoan()\n\
                             2. Returns wrong value or doesn't return at all\n\
                             3. Provider doesn't check return value\n\
                             4. May cause unexpected behavior\n\n\
                             Fix: require(returnValue == CALLBACK_SUCCESS)".to_string(),
                        location: flash_loan_pc,
                    });
                }
            }
        }

        vulnerabilities
    }

    // Helper methods

    fn find_flash_loan_function(&self) -> Option<usize> {
        let selector = [0x5c, 0xff, 0xe9, 0xde]; // flashLoan
        self.bytecode.windows(4).position(|w| w == selector)
    }

    fn find_max_flash_loan_function(&self) -> Option<usize> {
        let selector = [0x61, 0x32, 0x55, 0xab]; // maxFlashLoan
        self.bytecode.windows(4).position(|w| w == selector)
    }

    fn has_fee_calculation(&self, start: usize, distance: usize) -> bool {
        let end = (start + distance).min(self.bytecode.len());
        
        // Look for multiplication or division (fee calculation)
        self.bytecode[start..end].iter()
            .any(|&op| op == 0x02 || op == 0x04) // MUL or DIV
    }

    fn has_token_transfer_after(&self, start: usize, distance: usize) -> bool {
        let end = (start + distance).min(self.bytecode.len());
        
        // Look for transfer or transferFrom selector
        let transfer_sig = [0xa9, 0x05, 0x9c, 0xbb];
        
        self.bytecode[start..end].windows(4).any(|w| w == transfer_sig)
    }

    fn returns_max_uint256(&self, start: usize, distance: usize) -> bool {
        let end = (start + distance).min(self.bytecode.len());
        
        // Look for pattern: NOT(0) which gives MAX_UINT256
        for i in start..end.saturating_sub(2) {
            if self.bytecode[i] == 0x60 && // PUSH1
               self.bytecode[i + 1] == 0x00 && // 0
               self.bytecode.get(i + 2) == Some(&0x19) { // NOT
                return true;
            }
        }
        
        false
    }

    fn has_callback_call(&self, start: usize, distance: usize) -> bool {
        let end = (start + distance).min(self.bytecode.len());
        
        // onFlashLoan selector: 0x23e30c8b
        let callback_sig = [0x23, 0xe3, 0x0c, 0x8b];
        
        self.bytecode[start..end].windows(4).any(|w| w == callback_sig)
    }

    fn has_state_change_after_callback(&self, start: usize) -> bool {
        // Look for SSTORE after callback call
        if let Some(callback_pos) = self.bytecode[start..].windows(4)
            .position(|w| w == [0x23, 0xe3, 0x0c, 0x8b]) {
            
            let callback_pc = start + callback_pos;
            let search_end = (callback_pc + 100).min(self.bytecode.len());
            
            return self.bytecode[callback_pc..search_end].contains(&0x55); // SSTORE
        }
        
        false
    }

    fn has_reentrancy_guard(&self, start: usize, distance: usize) -> bool {
        let begin = start.saturating_sub(distance);
        
        // Look for ReentrancyGuard pattern
        for i in begin..start {
            if i + 3 < start {
                if self.bytecode[i] == 0x54 && // SLOAD
                   self.bytecode[i + 1] == 0x14 && // EQ
                   self.bytecode[i + 2] == 0x57 { // JUMPI
                    return true;
                }
            }
        }
        
        false
    }

    fn validates_callback_return(&self, start: usize, distance: usize) -> bool {
        let end = (start + distance).min(self.bytecode.len());
        
        // Look for EQ check after callback (comparing return value)
        if let Some(callback_pos) = self.bytecode[start..end].windows(4)
            .position(|w| w == [0x23, 0xe3, 0x0c, 0x8b]) {
            
            let callback_pc = start + callback_pos;
            let search_end = (callback_pc + 50).min(self.bytecode.len());
            
            return self.bytecode[callback_pc..search_end].contains(&0x14); // EQ
        }
        
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flash_loan_provider_detection() {
        let bytecode = vec![
            0x5c, 0xff, 0xe9, 0xde, // flashLoan selector
            0xFA, // STATICCALL
            // No fee calculation (no MUL/DIV)
            0x00, // STOP
        ];
        
        let detector = FlashMintProviderDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty(), "Should detect missing fee enforcement");
    }
}
