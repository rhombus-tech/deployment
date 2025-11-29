/// Donation Attack Detector
/// Detects Euler V1 style donation attacks where external token transfers
/// manipulate accounting without proper balance checks
/// 
/// Famous exploits: Euler V1 ($197M), Hundred Finance ($7M)

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DonationVulnerability {
    pub vulnerability_type: DonationAttackType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub affected_function: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DonationAttackType {
    MissingBalanceCheck,           // Uses cached balance instead of actual
    DirectTransferManipulation,    // Accepts direct transfers without tracking
    ShareInflationViaDonation,     // ERC-4626 style share manipulation
    ReserveManipulation,           // Manipulates protocol reserves
    AccountingBypassViaDonation,   // Bypasses deposit/withdraw accounting
}

pub struct DonationAttackDetector {
    bytecode: Vec<u8>,
}

impl DonationAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DonationVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern 1: balanceOf called but result stored, not re-checked
        vulnerabilities.extend(self.detect_cached_balance_pattern());

        // Pattern 2: State changes based on totalAssets without fresh balanceOf
        vulnerabilities.extend(self.detect_stale_balance_usage());

        // Pattern 3: Missing balance validation before critical operations
        vulnerabilities.extend(self.detect_unvalidated_balance_operations());

        // Pattern 4: Direct ERC20 transfers accepted without proper tracking
        vulnerabilities.extend(self.detect_untracked_transfers());

        vulnerabilities
    }

    /// Euler V1 pattern: balanceOf cached at function start, used later
    fn detect_cached_balance_pattern(&self) -> Vec<DonationVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(100) {
            // Look for: PUSH4 balanceOf_selector, then STATICCALL, then SSTORE
            if self.is_balance_of_call(pc) {
                let storage_pc = self.find_next_sstore(pc, 50);
                
                if let Some(store_pc) = storage_pc {
                    // Check if this balance is used later without re-checking
                    if self.has_later_usage_without_refresh(store_pc, 500) {
                        vulnerabilities.push(DonationVulnerability {
                            vulnerability_type: DonationAttackType::MissingBalanceCheck,
                            severity: SecuritySeverity::Critical,
                            confidence: 0.85,
                            description: format!(
                                "Cached balance pattern detected at PC {}. Contract stores balanceOf \
                                result and uses it later without re-checking. Attacker can donate tokens \
                                between cache and usage to manipulate accounting.",
                                pc
                            ),
                            affected_function: "Unknown".to_string(),
                            exploit_scenario: 
                                "1. Contract caches: cachedBalance = token.balanceOf(this)\n\
                                 2. Attacker donates: token.transfer(contract, X)\n\
                                 3. Contract uses cachedBalance (now wrong)\n\
                                 4. Attacker profits from inflated shares/accounting".to_string(),
                            location: pc,
                        });
                    }
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    /// Pattern: totalAssets/totalSupply calculation without fresh balanceOf
    fn detect_stale_balance_usage(&self) -> Vec<DonationVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(200) {
            // Look for division (shares calculation) using potentially stale balance
            if self.bytecode[pc] == 0x04 { // DIV opcode
                // Check if numerator comes from storage (stale) vs fresh CALL
                if self.has_storage_load_in_range(pc.saturating_sub(50), pc) {
                    let has_fresh_balance = self.has_balance_check_in_range(pc.saturating_sub(30), pc);
                    
                    if !has_fresh_balance {
                        vulnerabilities.push(DonationVulnerability {
                            vulnerability_type: DonationAttackType::DirectTransferManipulation,
                            severity: SecuritySeverity::High,
                            confidence: 0.75,
                            description: format!(
                                "Division operation at PC {} uses stored balance without fresh check. \
                                Vulnerable to donation attacks that manipulate stored totalAssets.",
                                pc
                            ),
                            affected_function: "Share calculation".to_string(),
                            exploit_scenario:
                                "1. shares = deposit * totalShares / totalAssets (cached)\n\
                                 2. Attacker donates to inflate totalAssets\n\
                                 3. Victim gets fewer shares than deserved\n\
                                 4. Attacker redeems inflated share value".to_string(),
                            location: pc,
                        });
                    }
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    /// Pattern: Critical operations without balance validation
    fn detect_unvalidated_balance_operations(&self) -> Vec<DonationVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(150) {
            // Look for mint/burn operations (MSTORE with large values)
            if self.is_mint_or_burn_pattern(pc) {
                // Check if there's a balance validation before this
                let has_validation = self.has_require_before(pc, 100);
                
                if !has_validation {
                    vulnerabilities.push(DonationVulnerability {
                        vulnerability_type: DonationAttackType::AccountingBypassViaDonation,
                        severity: SecuritySeverity::High,
                        confidence: 0.70,
                        description: format!(
                            "Mint/burn operation at PC {} lacks balance validation. \
                            May be vulnerable to donation-based accounting bypass.",
                            pc
                        ),
                        affected_function: "Mint/Burn".to_string(),
                        exploit_scenario:
                            "1. Contract mints shares based on assumptions\n\
                             2. Attacker donates to break assumptions\n\
                             3. Shares minted at wrong ratio\n\
                             4. Protocol suffers loss".to_string(),
                        location: pc,
                    });
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    /// Pattern: Accepts transfers without tracking mechanism
    fn detect_untracked_transfers(&self) -> Vec<DonationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Check if contract has receive()/fallback() for native ETH
        let has_receive = self.has_receive_function();
        let has_deposit_function = self.has_deposit_tracking();
        
        if has_receive && !has_deposit_function {
            vulnerabilities.push(DonationVulnerability {
                vulnerability_type: DonationAttackType::ReserveManipulation,
                severity: SecuritySeverity::Medium,
                confidence: 0.65,
                description: 
                    "Contract accepts native ETH via receive()/fallback() but may not track \
                    it properly. Vulnerable to reserve manipulation via direct ETH sends.".to_string(),
                affected_function: "receive/fallback".to_string(),
                exploit_scenario:
                    "1. Contract uses address(this).balance for calculations\n\
                     2. Attacker sends ETH directly (not via deposit)\n\
                     3. Balance-based calculations return wrong values\n\
                     4. Protocol logic breaks or becomes exploitable".to_string(),
                location: 0,
            });
        }

        vulnerabilities
    }

    // Helper methods
    
    fn is_balance_of_call(&self, pc: usize) -> bool {
        if pc + 4 >= self.bytecode.len() {
            return false;
        }
        
        // Look for balanceOf selector (0x70a08231)
        self.bytecode[pc..pc+4].windows(4).any(|w| {
            w == [0x63, 0x70, 0xa0, 0x82] || // PUSH4 0x70a08231
            w == [0x70, 0xa0, 0x82, 0x31]    // The selector itself
        })
    }

    fn find_next_sstore(&self, start_pc: usize, max_distance: usize) -> Option<usize> {
        let end = (start_pc + max_distance).min(self.bytecode.len());
        
        for i in start_pc..end {
            if self.bytecode[i] == 0x55 { // SSTORE
                return Some(i);
            }
        }
        None
    }

    fn has_later_usage_without_refresh(&self, sstore_pc: usize, search_distance: usize) -> bool {
        let end = (sstore_pc + search_distance).min(self.bytecode.len());
        
        // Look for SLOAD followed by arithmetic without intervening STATICCALL
        let mut found_sload = false;
        
        for i in (sstore_pc + 1)..end {
            if self.bytecode[i] == 0x54 { // SLOAD
                found_sload = true;
            }
            
            if found_sload {
                // Check if arithmetic happens before refresh
                if matches!(self.bytecode[i], 0x01..=0x05 | 0x10 | 0x11) { // ADD, MUL, SUB, DIV, MOD, LT, GT
                    // Check if there's a balanceOf call between SLOAD and arithmetic
                    let has_refresh = self.has_balance_check_in_range(sstore_pc + 1, i);
                    return !has_refresh;
                }
            }
        }
        
        false
    }

    fn has_balance_check_in_range(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        for i in start..range_end {
            if self.is_balance_of_call(i) {
                return true;
            }
        }
        false
    }

    fn has_storage_load_in_range(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        for i in start..range_end {
            if self.bytecode[i] == 0x54 { // SLOAD
                return true;
            }
        }
        false
    }

    fn is_mint_or_burn_pattern(&self, pc: usize) -> bool {
        // Look for MSTORE followed by LOG (Transfer event)
        if pc + 10 >= self.bytecode.len() {
            return false;
        }
        
        self.bytecode[pc] == 0x52 && // MSTORE
        self.bytecode[pc..pc+10].iter().any(|&op| op == 0xA0 || op == 0xA1 || op == 0xA2) // LOG
    }

    fn has_require_before(&self, pc: usize, distance: usize) -> bool {
        let start = pc.saturating_sub(distance);
        
        for i in start..pc {
            // REVERT or JUMPI (conditional checks)
            if self.bytecode[i] == 0xFD || self.bytecode[i] == 0x57 {
                return true;
            }
        }
        false
    }

    fn has_receive_function(&self) -> bool {
        // Look for empty function signature (receive())
        self.bytecode.windows(4).any(|w| w == [0x00, 0x00, 0x00, 0x00])
    }

    fn has_deposit_tracking(&self) -> bool {
        // Look for Transfer events or storage updates near ETH receive
        self.bytecode.iter().any(|&op| op == 0xA1 || op == 0xA2) // LOG events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_euler_pattern() {
        // Simplified Euler V1 vulnerable pattern
        let bytecode = vec![
            0x63, 0x70, 0xa0, 0x82, 0x31, // PUSH4 balanceOf
            0xFA, // STATICCALL
            0x55, // SSTORE (cache balance)
            // ... later usage without refresh
            0x54, // SLOAD (load cached balance)
            0x02, // MUL (use in calculation)
        ];
        
        let detector = DonationAttackDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty(), "Should detect Euler-style donation attack");
    }
}
