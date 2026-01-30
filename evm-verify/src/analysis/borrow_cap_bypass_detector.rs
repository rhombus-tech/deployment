/// Borrow Cap Bypass Detector
/// Detects ways to bypass lending protocol borrow caps (Aave, Compound, Euler)

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BorrowCapBypassVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

pub struct BorrowCapBypassDetector {
    bytecode: Vec<u8>,
}

impl BorrowCapBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BorrowCapBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_unchecked_borrow_increase());
        vulnerabilities.extend(self.detect_flash_loan_borrow_bypass());
        vulnerabilities.extend(self.detect_multi_asset_borrow_bypass());
        vulnerabilities
    }

    fn detect_unchecked_borrow_increase(&self) -> Vec<BorrowCapBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(250) {
            if self.is_borrow_operation(pc) {
                if !self.has_borrow_cap_check(pc, 200) {
                    vulnerabilities.push(BorrowCapBypassVulnerability {
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        description: format!(
                            "Borrow operation at PC {} doesn't check borrow cap. \
                            Users can exceed borrow limits causing protocol insolvency.",
                            pc
                        ),
                        exploit_scenario:
                            "Borrow Cap Bypass Attack:\n\
                             1. Protocol sets borrow cap for USDC: 50M\n\
                             2. Current borrows: 48M USDC\n\
                             3. Attacker deposits 10M ETH collateral\n\
                             4. Attacker borrows 5M USDC (no cap check)\n\
                             5. Total borrows: 53M (exceeds 50M cap)\n\
                             6. Protocol risk model assumes max 50M borrows\n\
                             7. Excess borrowing breaks collateralization ratios\n\
                             8. Can trigger insolvency during market downturn\n\n\
                             Real impact: Euler hack ($200M) involved similar cap bypass\n\n\
                             Fix:\n\
                             function borrow(address asset, uint256 amount) {\n\
                                 uint256 currentBorrows = totalBorrows[asset];\n\
                                 uint256 borrowCap = borrowCaps[asset];\n\
                                 \n\
                                 require(\n\
                                     borrowCap == 0 || currentBorrows + amount <= borrowCap,\n\
                                     'Borrow cap exceeded'\n\
                                 );\n\
                                 \n\
                                 _executeBorrow(asset, amount);\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_flash_loan_borrow_bypass(&self) -> Vec<BorrowCapBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(300) {
            if self.is_borrow_operation(pc) {
                if self.has_callback_pattern(pc, 250) && !self.has_flash_loan_protection(pc, 250) {
                    vulnerabilities.push(BorrowCapBypassVulnerability {
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: format!(
                            "Borrow with callback at PC {} vulnerable to flash loan bypass. \
                            Attacker can temporarily inflate collateral to exceed borrow caps.",
                            pc
                        ),
                        exploit_scenario:
                            "Flash Loan Borrow Cap Bypass:\n\
                             1. Borrow cap: 10M USDC\n\
                             2. Current borrows: 9M USDC\n\
                             3. Attacker takes 100M USDC flash loan\n\
                             4. Attacker deposits 100M USDC as collateral\n\
                             5. Collateral check passes (huge collateral)\n\
                             6. Attacker borrows 2M USDC (total now 11M, exceeds cap)\n\
                             7. Attacker withdraws most collateral\n\
                             8. Attacker repays flash loan\n\
                             9. Net result: Borrowed 2M with minimal collateral\n\
                             10. Borrow cap exceeded, position undercollateralized\n\n\
                             Fix:\n\
                             bool private inFlashLoan;\n\
                             \n\
                             modifier noFlashLoan() {\n\
                                 require(!inFlashLoan, 'Flash loan in progress');\n\
                                 _;\n\
                             }\n\
                             \n\
                             function borrow(uint256 amount) noFlashLoan {\n\
                                 // Check cap\n\
                                 require(totalBorrows + amount <= borrowCap);\n\
                                 // Also check user's sustained collateral over time\n\
                                 require(userCollateralAge[msg.sender] >= 1 hours);\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_multi_asset_borrow_bypass(&self) -> Vec<BorrowCapBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(280) {
            if self.is_borrow_operation(pc) {
                if self.has_multiple_asset_calls(pc, 300) && !self.has_aggregate_cap_check(pc, 300) {
                    vulnerabilities.push(BorrowCapBypassVulnerability {
                        severity: SecuritySeverity::High,
                        confidence: 0.70,
                        description: format!(
                            "Multi-asset borrow at PC {} doesn't check aggregate caps. \
                            Can bypass individual asset caps via correlated borrowing.",
                            pc
                        ),
                        exploit_scenario:
                            "Multi-Asset Borrow Cap Bypass:\n\
                             1. Protocol has USDC (cap: 50M) and USDT (cap: 50M)\n\
                             2. Both are USD stablecoins (highly correlated)\n\
                             3. Attacker borrows 49M USDC (near cap)\n\
                             4. Attacker also borrows 49M USDT (near cap)\n\
                             5. Total USD-denominated borrows: 98M\n\
                             6. Protocol risk model should limit total USD exposure\n\
                             7. But individual asset caps don't account for correlation\n\
                             8. If USDC or USDT depegs, both positions fail simultaneously\n\n\
                             Compound V2 vulnerability pattern\n\n\
                             Fix:\n\
                             // Group correlated assets\n\
                             mapping(bytes32 => uint256) public assetGroupCaps;\n\
                             mapping(address => bytes32) public assetToGroup;\n\
                             \n\
                             function borrow(address asset, uint256 amount) {\n\
                                 // Check individual cap\n\
                                 require(totalBorrows[asset] + amount <= borrowCaps[asset]);\n\
                                 \n\
                                 // Check group cap (e.g., 'USD_STABLECOINS')\n\
                                 bytes32 group = assetToGroup[asset];\n\
                                 if (group != bytes32(0)) {\n\
                                     uint256 groupTotal = 0;\n\
                                     for (address a : assetsInGroup[group]) {\n\
                                         groupTotal += totalBorrows[a];\n\
                                     }\n\
                                     require(groupTotal + amount <= assetGroupCaps[group]);\n\
                                 }\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn is_borrow_operation(&self, pc: usize) -> bool {
        if pc + 120 >= self.bytecode.len() { return false; }
        // Look for transfer + debt tracking patterns
        let mut has_transfer = false;
        let mut has_debt_update = false;
        
        for i in pc..(pc + 120).min(self.bytecode.len()) {
            // transferFrom or transfer
            if self.bytecode[i..].windows(4).take(30).any(|w| w == [0xa9, 0x05, 0x9c, 0xbb] || w == [0x23, 0xb8, 0x72, 0xdd]) {
                has_transfer = true;
            }
            // SSTORE (debt update)
            if self.bytecode[i] == 0x55 {
                has_debt_update = true;
            }
        }
        
        has_transfer && has_debt_update
    }

    fn has_borrow_cap_check(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range);
        let mut has_sload = false;
        let mut has_comparison = false;
        
        for i in start..pc {
            if self.bytecode[i] == 0x54 { // SLOAD (loading cap)
                has_sload = true;
            }
            if has_sload && matches!(self.bytecode[i], 0x10 | 0x11) { // LT or GT
                for j in (i + 1)..(i + 15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xfd { // REVERT
                        has_comparison = true;
                        break;
                    }
                }
            }
        }
        
        has_sload && has_comparison
    }

    fn has_callback_pattern(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        for i in pc..end {
            if matches!(self.bytecode[i], 0xf1 | 0xf2 | 0xf4) { // CALL, CALLCODE, DELEGATECALL
                return true;
            }
        }
        false
    }

    fn has_flash_loan_protection(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        
        // Look for reentrancy guard pattern or flash loan flag check
        let mut has_guard_check = false;
        for i in start..end {
            if self.bytecode[i] == 0x54 { // SLOAD
                // Check if followed by ISZERO and conditional revert
                for j in (i + 1)..(i + 10).min(end) {
                    if self.bytecode[j] == 0x15 { // ISZERO
                        for k in (j + 1)..(j + 10).min(end) {
                            if self.bytecode[k] == 0xfd {
                                has_guard_check = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        has_guard_check
    }

    fn has_multiple_asset_calls(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        let mut asset_refs = 0;
        
        for i in pc..end {
            // Look for external calls or SLOADs (multiple assets)
            if matches!(self.bytecode[i], 0xf1 | 0xfa | 0x54) {
                asset_refs += 1;
            }
        }
        
        asset_refs >= 3
    }

    fn has_aggregate_cap_check(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        
        // Look for loop-like pattern (checking multiple assets)
        let mut sload_count = 0;
        let mut has_add = false;
        
        for i in start..end {
            if self.bytecode[i] == 0x54 { sload_count += 1; }
            if self.bytecode[i] == 0x01 { has_add = true; } // ADD (aggregating)
        }
        
        // Multiple SLOADs + ADD suggests aggregate calculation
        sload_count >= 3 && has_add
    }
}
