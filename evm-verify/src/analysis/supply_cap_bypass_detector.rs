/// Supply Cap Bypass Detector
/// Detects ways to bypass lending protocol supply caps (Aave, Compound, etc.)

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyCapBypassVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

pub struct SupplyCapBypassDetector {
    bytecode: Vec<u8>,
}

impl SupplyCapBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SupplyCapBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_unchecked_supply_increase());
        vulnerabilities.extend(self.detect_cross_market_bypass());
        vulnerabilities.extend(self.detect_cap_check_after_state_change());
        vulnerabilities
    }

    fn detect_unchecked_supply_increase(&self) -> Vec<SupplyCapBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(250) {
            if self.is_supply_operation(pc) {
                if !self.has_cap_check_before_mint(pc, 200) {
                    vulnerabilities.push(SupplyCapBypassVulnerability {
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        description: format!(
                            "Supply operation at PC {} doesn't check cap before minting. \
                            Attackers can exceed supply limits causing protocol insolvency.",
                            pc
                        ),
                        exploit_scenario:
                            "Supply Cap Bypass:\n\
                             1. Protocol sets supply cap: 10M USDC\n\
                             2. Current supply: 9.5M USDC\n\
                             3. Attacker deposits 1M USDC\n\
                             4. No cap check before mint\n\
                             5. totalSupply becomes 10.5M (exceeds cap)\n\
                             6. Protocol risk parameters calculated for 10M max\n\
                             7. Excess supply breaks risk model\n\
                             8. Can trigger cascading liquidations\n\n\
                             Fix:\n\
                             function supply(uint256 amount) {\n\
                                 uint256 newSupply = totalSupply() + amount;\n\
                                 require(newSupply <= supplyCap, 'Supply cap exceeded');\n\
                                 _mint(msg.sender, amount);\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_cross_market_bypass(&self) -> Vec<SupplyCapBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(200) {
            if self.is_supply_operation(pc) {
                if self.has_multiple_market_calls(pc, 300) && !self.has_global_cap_check(pc, 300) {
                    vulnerabilities.push(SupplyCapBypassVulnerability {
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: format!(
                            "Multi-market supply at PC {} doesn't check global cap. \
                            Can bypass per-market caps via cross-market deposits.",
                            pc
                        ),
                        exploit_scenario:
                            "Cross-Market Cap Bypass:\n\
                             1. Protocol has USDC in Market A (cap: 10M) and Market B (cap: 10M)\n\
                             2. Both markets nearly full: A=9.8M, B=9.8M\n\
                             3. Attacker deposits 500K in Market A (total 10.3M, exceeds cap)\n\
                             4. Check only looks at individual market\n\
                             5. Attacker also deposits 500K in Market B\n\
                             6. Total USDC exposure: 20.6M (should be max 20M)\n\
                             7. Protocol now over-leveraged\n\n\
                             Fix:\n\
                             mapping(address => uint256) public globalSupplyCaps;\n\
                             mapping(address => mapping(address => uint256)) public marketSupply;\n\
                             \n\
                             function supply(address market, uint256 amount) {\n\
                                 uint256 totalAcrossMarkets = 0;\n\
                                 for (address m : markets) {\n\
                                     totalAcrossMarkets += marketSupply[token][m];\n\
                                 }\n\
                                 require(totalAcrossMarkets + amount <= globalSupplyCaps[token]);\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_cap_check_after_state_change(&self) -> Vec<SupplyCapBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(220) {
            if self.is_supply_operation(pc) {
                if let Some(sstore_pc) = self.find_sstore_before(pc, 100) {
                    if self.has_cap_check_after(sstore_pc, pc) {
                        vulnerabilities.push(SupplyCapBypassVulnerability {
                            severity: SecuritySeverity::High,
                            confidence: 0.70,
                            description: format!(
                                "Supply cap check at PC {} happens AFTER state update. \
                                Reentrancy can bypass cap during state inconsistency window.",
                                pc
                            ),
                            exploit_scenario:
                                "Reentrancy Cap Bypass:\n\
                                 1. Contract updates supply: totalSupply += amount (SSTORE)\n\
                                 2. Contract transfers tokens (external call)\n\
                                 3. Attacker re-enters during transfer\n\
                                 4. totalSupply already increased\n\
                                 5. Cap check happens after re-entrance\n\
                                 6. Attacker supplies again before cap check\n\
                                 7. Both supplies succeed, total exceeds cap\n\n\
                                 Fix:\n\
                                 function supply(uint256 amount) nonReentrant {\n\
                                     // CHECK first\n\
                                     require(totalSupply() + amount <= supplyCap);\n\
                                     // EFFECTS second\n\
                                     _mint(msg.sender, amount);\n\
                                     // INTERACTIONS last\n\
                                     token.transferFrom(msg.sender, this, amount);\n\
                                 }".to_string(),
                            location: pc,
                        });
                    }
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn is_supply_operation(&self, pc: usize) -> bool {
        if pc + 100 >= self.bytecode.len() { return false; }
        // Look for mint/supply patterns
        let mut has_transfer = false;
        let mut has_mint = false;
        for i in pc..(pc + 100).min(self.bytecode.len()) {
            if self.bytecode[i..].windows(4).take(20).any(|w| w == [0x23, 0xb8, 0x72, 0xdd]) {
                has_transfer = true;
            }
            if self.bytecode[i] == 0xa2 { has_mint = true; } // LOG3
        }
        has_transfer && has_mint
    }

    fn has_cap_check_before_mint(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range);
        for i in start..pc {
            if matches!(self.bytecode[i], 0x10 | 0x11) { // LT or GT
                for j in (i + 1)..(i + 15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xfd { return true; }
                }
            }
        }
        false
    }

    fn has_multiple_market_calls(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        let mut external_calls = 0;
        for i in pc..end {
            if matches!(self.bytecode[i], 0xf1 | 0xfa) {
                external_calls += 1;
            }
        }
        external_calls >= 2
    }

    fn has_global_cap_check(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        let mut sload_count = 0;
        for i in start..end {
            if self.bytecode[i] == 0x54 { sload_count += 1; }
        }
        sload_count >= 3 // Multiple SLOADs suggest global aggregation
    }

    fn find_sstore_before(&self, pc: usize, range: usize) -> Option<usize> {
        let start = pc.saturating_sub(range);
        for i in (start..pc).rev() {
            if self.bytecode[i] == 0x55 { return Some(i); }
        }
        None
    }

    fn has_cap_check_after(&self, start: usize, end: usize) -> bool {
        for i in start..end.min(self.bytecode.len()) {
            if matches!(self.bytecode[i], 0x10 | 0x11) {
                return true;
            }
        }
        false
    }
}
