/// Recursive Borrowing Detector
/// Detects recursive borrowing loops that can amplify leverage beyond safe limits

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecursiveBorrowingVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

pub struct RecursiveBorrowingDetector {
    bytecode: Vec<u8>,
}

impl RecursiveBorrowingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<RecursiveBorrowingVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(300) {
            if self.is_borrow_deposit_loop(pc) {
                if !self.has_recursion_protection(pc, 250) {
                    vulnerabilities.push(RecursiveBorrowingVulnerability {
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        description: format!(
                            "Recursive borrow-deposit loop at PC {} allows unlimited leverage amplification",
                            pc
                        ),
                        exploit_scenario:
                            "Recursive Borrowing Attack:\n\
                             1. User deposits 100 ETH as collateral\n\
                             2. User borrows 80 ETH (80% LTV)\n\
                             3. User deposits 80 ETH back as collateral\n\
                             4. User borrows 64 ETH (80% of 80 ETH)\n\
                             5. User deposits 64 ETH as collateral\n\
                             6. Repeat loop 10 times\n\
                             7. Final position: 100 ETH deposit → 400+ ETH borrowed\n\
                             8. Actual leverage: 5x (should be 1.25x max)\n\
                             9. Tiny price move liquidates position\n\
                             10. Protocol left with bad debt\n\n\
                             Fix:\n\
                             mapping(address => bool) private inBorrow;\n\
                             \n\
                             function borrow(uint256 amount) {\n\
                                 require(!inBorrow[msg.sender], 'Recursive borrow');\n\
                                 inBorrow[msg.sender] = true;\n\
                                 \n\
                                 _executeBorrow(amount);\n\
                                 \n\
                                 inBorrow[msg.sender] = false;\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn is_borrow_deposit_loop(&self, pc: usize) -> bool {
        if pc + 300 >= self.bytecode.len() { return false; }
        
        let mut has_borrow = false;
        let mut has_deposit = false;
        let mut has_loop = false;
        
        for i in pc..(pc + 300).min(self.bytecode.len()) {
            if self.bytecode[i..].windows(4).take(50).any(|w| w == [0x23, 0xb8, 0x72, 0xdd]) {
                has_borrow = true;
            }
            if has_borrow && self.bytecode[i..].windows(4).take(50).any(|w| w == [0xa9, 0x05, 0x9c, 0xbb]) {
                has_deposit = true;
            }
            if matches!(self.bytecode[i], 0x56 | 0x57) {
                has_loop = true;
            }
        }
        
        has_borrow && has_deposit && has_loop
    }

    fn has_recursion_protection(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        
        let mut has_flag_check = false;
        for i in start..end {
            if self.bytecode[i] == 0x54 { // SLOAD
                for j in (i+1)..(i+10).min(end) {
                    if self.bytecode[j] == 0x15 { // ISZERO
                        for k in (j+1)..(j+10).min(end) {
                            if self.bytecode[k] == 0xfd {
                                has_flag_check = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
        has_flag_check
    }
}
