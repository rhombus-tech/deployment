/// Sanity Check Absence Detector
/// 
/// Detects missing business logic validations (37% of exploits per ArXiv study)
/// Real impact: $1.1B+ in preventable exploits
/// 
/// Example: Thala Hack (Nov 2024) - $25.5M
/// Missing: require(withdrawal <= stakedBalance)
/// 
/// Patterns detected:
/// - withdrawal without balance check
/// - burn without supply check
/// - claim without entitlement check
/// - transfer from/to zero address check
/// - division by zero check
/// - array bounds check
/// - state prerequisite check

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanityCheckAbsenceVulnerability {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub missing_check_type: MissingCheckType,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub confidence: f32,
    pub real_world_example: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MissingCheckType {
    WithdrawalBalanceCheck,      // withdraw > balance
    BurnSupplyCheck,             // burn > totalSupply
    ClaimEntitlementCheck,       // claim > entitled
    TransferZeroAddress,         // transfer to/from address(0)
    DivisionByZero,              // x / y without y != 0
    ArrayBoundsCheck,            // array[i] without i < length
    AmountNonZero,               // operation with amount = 0
    StatePrerequisite,           // operation before initialization
    BalanceUnderflow,            // balance - amount without check
    SupplyOverflow,              // totalSupply + amount without cap
    RatioMaintenance,            // collateral/debt ratio not checked
    MinimumThreshold,            // value below minimum not rejected
}

pub struct SanityCheckAbsenceDetector {
    bytecode: Vec<u8>,
}

impl SanityCheckAbsenceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SanityCheckAbsenceVulnerability> {
        let mut vulnerabilities = Vec::new();

        // 1. Withdrawal without balance check (Thala $25.5M)
        vulnerabilities.extend(self.detect_missing_withdrawal_check());

        // 2. Burn without supply check
        vulnerabilities.extend(self.detect_missing_burn_check());

        // 3. Claim without entitlement check
        vulnerabilities.extend(self.detect_missing_claim_check());

        // 4. Transfer to/from zero address
        vulnerabilities.extend(self.detect_missing_zero_address_check());

        // 5. Division by zero
        vulnerabilities.extend(self.detect_missing_division_check());

        // 6. Array bounds check
        vulnerabilities.extend(self.detect_missing_array_bounds());

        // 7. Amount non-zero check
        vulnerabilities.extend(self.detect_missing_amount_check());

        // 8. State prerequisite check
        vulnerabilities.extend(self.detect_missing_state_prerequisite());

        vulnerabilities
    }

    fn detect_missing_withdrawal_check(&self) -> Vec<SanityCheckAbsenceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: CALLDATALOAD (amount) → SSTORE/transfer
            // WITHOUT: SLOAD (balance) → comparison
            if self.has_withdrawal_without_balance_check(pc) {
                vulns.push(SanityCheckAbsenceVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    missing_check_type: MissingCheckType::WithdrawalBalanceCheck,
                    description: "Withdrawal operation without checking user balance".to_string(),
                    exploit_scenario: "function withdraw(uint amount) {\n\
                        // Missing: require(balances[msg.sender] >= amount);\n\
                        balances[msg.sender] -= amount; // Can underflow!\n\
                        token.transfer(msg.sender, amount);\n\
                        }\n\
                        \n\
                        Thala Hack (Nov 2024) - $25.5M:\n\
                        - User unstaked with ZERO balance\n\
                        - Withdrew millions without check\n\
                        - Missing: require(withdrawal <= stakedBalance)".to_string(),
                    remediation: "Add balance check: require(balances[msg.sender] >= amount, 'Insufficient balance')".to_string(),
                    confidence: 0.90,
                    real_world_example: "Thala Protocol - Nov 2024 - $25.5M".to_string(),
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_missing_burn_check(&self) -> Vec<SanityCheckAbsenceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: totalSupply -= amount WITHOUT checking amount <= totalSupply
            if self.has_burn_without_supply_check(pc) {
                vulns.push(SanityCheckAbsenceVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    missing_check_type: MissingCheckType::BurnSupplyCheck,
                    description: "Token burn without validating against total supply".to_string(),
                    exploit_scenario: "function burn(uint amount) {\n\
                        // Missing: require(amount <= totalSupply);\n\
                        totalSupply -= amount; // Can underflow!\n\
                        }\n\
                        \n\
                        Attacker burns more than supply:\n\
                        - totalSupply underflows to max uint\n\
                        - Protocol accounting corrupted\n\
                        - Can mint infinite tokens".to_string(),
                    remediation: "Add supply check: require(amount <= totalSupply, 'Burn exceeds supply')".to_string(),
                    confidence: 0.85,
                    real_world_example: "Multiple protocols - supply underflow exploits".to_string(),
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_missing_claim_check(&self) -> Vec<SanityCheckAbsenceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Transfer reward WITHOUT checking entitled amount
            if self.has_claim_without_entitlement_check(pc) {
                vulns.push(SanityCheckAbsenceVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    missing_check_type: MissingCheckType::ClaimEntitlementCheck,
                    description: "Reward claim without validating user's entitled amount".to_string(),
                    exploit_scenario: "function claimRewards(uint amount) {\n\
                        // Missing: require(amount <= calculateRewards(msg.sender));\n\
                        rewards.transfer(msg.sender, amount);\n\
                        }\n\
                        \n\
                        Attacker claims unlimited rewards:\n\
                        - No check against earned rewards\n\
                        - Drains entire reward pool\n\
                        - Protocol insolvency".to_string(),
                    remediation: "Add entitlement check: require(amount <= earned[msg.sender], 'Exceeds entitled')".to_string(),
                    confidence: 0.88,
                    real_world_example: "Reward manipulation exploits - $200M+".to_string(),
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_missing_zero_address_check(&self) -> Vec<SanityCheckAbsenceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Transfer to address parameter WITHOUT zero check
            if self.has_transfer_without_zero_check(pc) {
                vulns.push(SanityCheckAbsenceVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Medium,
                    missing_check_type: MissingCheckType::TransferZeroAddress,
                    description: "Transfer to address without checking for zero address".to_string(),
                    exploit_scenario: "function transfer(address to, uint amount) {\n\
                        // Missing: require(to != address(0));\n\
                        balances[to] += amount;\n\
                        }\n\
                        \n\
                        Tokens sent to zero address:\n\
                        - Funds permanently locked\n\
                        - Reduces circulating supply\n\
                        - User loses funds".to_string(),
                    remediation: "Add zero address check: require(to != address(0), 'Transfer to zero address')".to_string(),
                    confidence: 0.75,
                    real_world_example: "Common bug - billions lost to address(0)".to_string(),
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_missing_division_check(&self) -> Vec<SanityCheckAbsenceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: DIV operation WITHOUT checking divisor != 0
            if self.has_division_without_zero_check(pc) {
                vulns.push(SanityCheckAbsenceVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    missing_check_type: MissingCheckType::DivisionByZero,
                    description: "Division operation without checking divisor is non-zero".to_string(),
                    exploit_scenario: "function calculatePrice(uint reserves) {\n\
                        // Missing: require(reserves != 0);\n\
                        return totalValue / reserves; // Reverts if reserves = 0\n\
                        }\n\
                        \n\
                        DOS attack:\n\
                        - Attacker drains reserves to 0\n\
                        - All price calculations revert\n\
                        - Protocol frozen".to_string(),
                    remediation: "Add zero check: require(divisor != 0, 'Division by zero')".to_string(),
                    confidence: 0.80,
                    real_world_example: "AMM/vault price calculation DOS".to_string(),
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_missing_array_bounds(&self) -> Vec<SanityCheckAbsenceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Array access WITHOUT length check
            if self.has_array_access_without_bounds(pc) {
                vulns.push(SanityCheckAbsenceVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    missing_check_type: MissingCheckType::ArrayBoundsCheck,
                    description: "Array access without validating index is within bounds".to_string(),
                    exploit_scenario: "function getUser(uint index) {\n\
                        // Missing: require(index < users.length);\n\
                        return users[index]; // OOB if index >= length\n\
                        }\n\
                        \n\
                        Out of bounds access:\n\
                        - Reads arbitrary storage\n\
                        - Information leak\n\
                        - Potential privilege escalation".to_string(),
                    remediation: "Add bounds check: require(index < array.length, 'Index out of bounds')".to_string(),
                    confidence: 0.78,
                    real_world_example: "Storage slot confusion exploits".to_string(),
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_missing_amount_check(&self) -> Vec<SanityCheckAbsenceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: State-changing operation allowing amount = 0
            if self.has_operation_allowing_zero_amount(pc) {
                vulns.push(SanityCheckAbsenceVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Medium,
                    missing_check_type: MissingCheckType::AmountNonZero,
                    description: "Operation allows amount = 0, enabling free actions or state manipulation".to_string(),
                    exploit_scenario: "function deposit(uint amount) {\n\
                        // Missing: require(amount > 0);\n\
                        updateRewards(); // Expensive operation\n\
                        balances[msg.sender] += amount; // += 0 is no-op\n\
                        }\n\
                        \n\
                        Griefing attack:\n\
                        - Attacker calls with amount = 0\n\
                        - Triggers gas-expensive reward update\n\
                        - No actual deposit\n\
                        - DOS via gas exhaustion".to_string(),
                    remediation: "Add amount check: require(amount > 0, 'Amount must be positive')".to_string(),
                    confidence: 0.72,
                    real_world_example: "Gas griefing attacks".to_string(),
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_missing_state_prerequisite(&self) -> Vec<SanityCheckAbsenceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Operation WITHOUT checking prerequisite state
            if self.has_operation_without_state_check(pc) {
                vulns.push(SanityCheckAbsenceVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    missing_check_type: MissingCheckType::StatePrerequisite,
                    description: "Operation executes without checking required state prerequisites".to_string(),
                    exploit_scenario: "function finalize() {\n\
                        // Missing: require(initialized);\n\
                        // Missing: require(endTime < block.timestamp);\n\
                        distributeRewards();\n\
                        }\n\
                        \n\
                        Premature execution:\n\
                        - Called before initialization\n\
                        - Called before vesting ends\n\
                        - State inconsistency\n\
                        - Protocol corruption".to_string(),
                    remediation: "Add state checks: require(initialized && ready, 'Prerequisites not met')".to_string(),
                    confidence: 0.85,
                    real_world_example: "Uninitialized contract exploits - $150M+".to_string(),
                });
            }

            pc += 1;
        }

        vulns
    }

    // Helper functions for pattern detection

    fn has_withdrawal_without_balance_check(&self, start: usize) -> bool {
        if start + 40 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 40];

        // Look for: SUB (balance -= amount) or transfer WITHOUT prior balance check
        let has_subtraction = window.iter().any(|&b| b == 0x03); // SUB
        let has_transfer = window.windows(4).any(|w| w == [0xa9, 0x05, 0x9c, 0xbb]); // transfer()

        if has_subtraction || has_transfer {
            // Check if there's a balance comparison before
            let has_balance_check = window.windows(3).any(|w| {
                w[0] == 0x54 && // SLOAD (balance)
                (w[1] == 0x10 || w[1] == 0x11) && // LT or GT
                w[2] == 0x57 // JUMPI (revert if insufficient)
            });

            !has_balance_check
        } else {
            false
        }
    }

    fn has_burn_without_supply_check(&self, start: usize) -> bool {
        if start + 30 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 30];

        // Look for: totalSupply SUB WITHOUT supply >= amount check
        let has_supply_sub = window.windows(2).any(|w| {
            if w[0] == 0x54 { // SLOAD (totalSupply)
                if let Some(pos) = window.iter().position(|&b| b == w[0]) {
                    if pos + 2 < window.len() {
                        return window[pos + 2] == 0x03; // SUB
                    }
                }
            }
            false
        });

        if has_supply_sub {
            // Check if there's a supply comparison
            !window.windows(2).any(|w| {
                (w[0] == 0x10 || w[0] == 0x11) && // LT or GT  
                w[1] == 0x57 // JUMPI
            })
        } else {
            false
        }
    }

    fn has_claim_without_entitlement_check(&self, start: usize) -> bool {
        if start + 35 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 35];

        // Look for: transfer (reward) WITHOUT entitlement read/check
        let has_transfer = window.windows(4).any(|w| w == [0xa9, 0x05, 0x9c, 0xbb]);

        if has_transfer {
            // Check if there's an entitlement/earned amount check
            let has_entitlement_check = window.windows(4).any(|w| {
                w[0] == 0x54 && // SLOAD (earned/entitled)
                w[1] == 0x35 && // CALLDATALOAD (amount)
                (w[2] == 0x10 || w[2] == 0x11) && // LT or GT
                w[3] == 0x57 // JUMPI
            });

            !has_entitlement_check
        } else {
            false
        }
    }

    fn has_transfer_without_zero_check(&self, start: usize) -> bool {
        if start + 25 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 25];

        // Look for: address parameter used WITHOUT zero check
        let has_address_use = window.iter().any(|&b| b == 0x35); // CALLDATALOAD (address)

        if has_address_use {
            // Check if there's a zero address comparison
            let has_zero_check = window.windows(3).any(|w| {
                w[0] == 0x15 && // ISZERO (addr == 0)
                w[1] == 0x15 && // ISZERO (invert)
                w[2] == 0x57 // JUMPI (revert if zero)
            });

            !has_zero_check
        } else {
            false
        }
    }

    fn has_division_without_zero_check(&self, start: usize) -> bool {
        if start + 20 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 20];

        // Look for: DIV WITHOUT prior zero check on divisor
        if let Some(div_pos) = window.iter().position(|&b| b == 0x04) {
            // Check if there's a zero check before DIV
            let before_div = &window[..div_pos];
            let has_zero_check = before_div.windows(2).any(|w| {
                w[0] == 0x15 && // ISZERO
                w[1] == 0x57 // JUMPI (revert if zero)
            });

            !has_zero_check
        } else {
            false
        }
    }

    fn has_array_access_without_bounds(&self, start: usize) -> bool {
        if start + 25 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 25];

        // Look for: array access (SLOAD with computed slot) WITHOUT length check
        let has_array_access = window.windows(2).any(|w| {
            w[0] == 0x20 && // SHA3 (array slot computation)
            w[1] == 0x54 // SLOAD (array element)
        });

        if has_array_access {
            // Check if there's a length comparison
            let has_bounds_check = window.windows(3).any(|w| {
                w[0] == 0x54 && // SLOAD (length)
                w[1] == 0x10 && // LT (index < length)
                w[2] == 0x57 // JUMPI
            });

            !has_bounds_check
        } else {
            false
        }
    }

    fn has_operation_allowing_zero_amount(&self, start: usize) -> bool {
        if start + 30 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 30];

        // Look for: state-changing operation WITHOUT amount > 0 check
        let has_state_change = window.iter().any(|&b| b == 0x55); // SSTORE

        if has_state_change {
            // Check if there's an amount > 0 check
            let has_nonzero_check = window.windows(4).any(|w| {
                w[0] == 0x35 && // CALLDATALOAD (amount)
                w[1] == 0x15 && // ISZERO (amount == 0)
                w[2] == 0x15 && // ISZERO (invert)
                w[3] == 0x57 // JUMPI (revert if zero)
            });

            !has_nonzero_check
        } else {
            false
        }
    }

    fn has_operation_without_state_check(&self, start: usize) -> bool {
        if start + 30 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 30];

        // Look for: critical operation WITHOUT initialization/state check
        let has_critical_op = window.iter().any(|&b| {
            b == 0xF1 || // CALL
            b == 0x55 // SSTORE
        });

        if has_critical_op {
            // Check if there's a state flag check before
            let has_state_check = window.windows(3).any(|w| {
                w[0] == 0x54 && // SLOAD (state flag)
                w[1] == 0x15 && // ISZERO
                w[2] == 0x57 // JUMPI (revert if not initialized)
            });

            !has_state_check
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_withdrawal_without_balance_check() {
        // Bytecode: SUB without balance check
        let bytecode = vec![
            0x03, // SUB (balance -= amount)
            0xa9, 0x05, 0x9c, 0xbb, // transfer()
            // No SLOAD → LT → JUMPI pattern
        ];
        
        let detector = SanityCheckAbsenceDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.missing_check_type, MissingCheckType::WithdrawalBalanceCheck)));
    }
}
