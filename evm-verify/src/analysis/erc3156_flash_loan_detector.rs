/// ERC-3156 Flash Loan Standard Detector
///
/// Detects vulnerabilities in ERC-3156 flash loan implementations.

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc3156Vulnerability {
    pub vulnerability_type: Erc3156VulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc3156VulnerabilityType {
    CallbackManipulation,           // onFlashLoan callback exploited
    FeeBypass,                      // Flash loan fee bypassed
    InitiatorValidation,            // Initiator not validated
    ReceiverValidation,             // Receiver validation missing
    MaxFlashLoanExceeded,           // maxFlashLoan limit bypassed
    FlashFeeManipulation,           // flashFee calculation exploited
    ReentrancyViaCallback,          // Reentrancy through flash loan
    ReturnDataValidation,           // Return value not checked
    BalanceManipulation,            // Balance check manipulated
    FlashLoanDOS,                   // DOS flash loan mechanism
}

pub struct Erc3156FlashLoanDetector {
    bytecode: Vec<u8>,
}

impl Erc3156FlashLoanDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Erc3156Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            let mut has_flash_loan = false;
            let mut validates_callback = false;
            let mut has_reentrancy_guard = false;
            
            for j in i..self.bytecode.len().min(i + 30) {
                if self.bytecode[j] == 0xF1 { // CALL (flash loan callback)
                    has_flash_loan = true;
                }
                if self.bytecode[j] == 0x3D && j + 1 < self.bytecode.len() && self.bytecode[j+1] == 0x14 { // RETURNDATASIZE EQ
                    validates_callback = true;
                }
                if self.bytecode[j] == 0x54 && j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x15 {
                    has_reentrancy_guard = true;
                }
            }
            
            if has_flash_loan && !validates_callback {
                vulnerabilities.push(Erc3156Vulnerability {
                    vulnerability_type: Erc3156VulnerabilityType::CallbackManipulation,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Flash loan callback return value not validated per ERC-3156.".to_string(),
                    exploit_scenario: "1. Attacker borrows 1M USDC via flashLoan\n\
                                      2. onFlashLoan callback executes malicious code\n\
                                      3. Returns incorrect magic value\n\
                                      4. Lender doesn't validate return\n\
                                      5. Attacker keeps 1M USDC without repaying\n\
                                      6. $1M stolen via callback exploit".to_string(),
                    recommendation: "Validate callback returns keccak256('ERC3156FlashBorrower.onFlashLoan'). \
                                  Add reentrancy guard. Check balances before/after.".to_string(),
                });
            }
            
            if has_flash_loan && !has_reentrancy_guard {
                vulnerabilities.push(Erc3156Vulnerability {
                    vulnerability_type: Erc3156VulnerabilityType::ReentrancyViaCallback,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Flash loan lacks reentrancy protection during callback.".to_string(),
                    exploit_scenario: "1. Flashloan 500 ETH\n\
                                      2. Callback reenters flashLoan again\n\
                                      3. Nested flash loan approved\n\
                                      4. Total borrowed: 1000 ETH with 500 ETH collateral\n\
                                      5. Attacker defaults on inner loan\n\
                                      6. $500K stolen via flash loan reentrancy".to_string(),
                    recommendation: "Add nonReentrant modifier to flashLoan(). Update state before callback.".to_string(),
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
    fn test_callback_manipulation() {
        let bytecode = vec![
            0xF1, // CALL (no validation)
        ];
        
        let detector = Erc3156FlashLoanDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty());
    }
}
