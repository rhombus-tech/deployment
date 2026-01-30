use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialWithdrawalGriefingVulnerability {
    pub location: usize,
    pub griefing_type: PartialWithdrawalGriefingType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PartialWithdrawalGriefingType {
    WithdrawalQueueManipulation,     // Manipulate queue to block partial withdrawals
    MinimumWithdrawalBypass,         // Set minimum to block small partial withdrawals
    GasGriefingAttack,               // Make withdrawals prohibitively expensive
    ReentrancyDuringPartialWithdraw, // Reenter during partial withdrawal
    WithdrawalFeeManipulation,       // Manipulate fees to grief withdrawals
    DelayAttackOnPartialWithdraw,    // Artificially delay partial withdrawals
}

pub struct PartialWithdrawalGriefingDetector {
    bytecode: Vec<u8>,
}

impl PartialWithdrawalGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PartialWithdrawalGriefingVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_queue_manipulation() {
            vulnerabilities.push(PartialWithdrawalGriefingVulnerability {
                location: loc,
                griefing_type: PartialWithdrawalGriefingType::WithdrawalQueueManipulation,
                severity: "High".to_string(),
                description: "Withdrawal queue can be manipulated to block specific partial withdrawals. \
                             Attacker can spam queue or reorder to prevent legitimate withdrawals from \
                             processing.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_minimum_withdrawal_bypass() {
            vulnerabilities.push(PartialWithdrawalGriefingVulnerability {
                location: loc,
                griefing_type: PartialWithdrawalGriefingType::MinimumWithdrawalBypass,
                severity: "Medium".to_string(),
                description: "Minimum withdrawal amount can be set arbitrarily high to block partial \
                             withdrawals. Protocol parameter can be manipulated to grief small withdrawals.".to_string(),
                confidence: 0.84,
            });
        }

        if let Some(loc) = self.detect_gas_griefing() {
            vulnerabilities.push(PartialWithdrawalGriefingVulnerability {
                location: loc,
                griefing_type: PartialWithdrawalGriefingType::GasGriefingAttack,
                severity: "High".to_string(),
                description: "Withdrawal processing can be made prohibitively gas-expensive through \
                             unbounded loops or state bloat. Makes partial withdrawals economically \
                             infeasible.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_reentrancy_during_withdrawal() {
            vulnerabilities.push(PartialWithdrawalGriefingVulnerability {
                location: loc,
                griefing_type: PartialWithdrawalGriefingType::ReentrancyDuringPartialWithdraw,
                severity: "Critical".to_string(),
                description: "Partial withdrawal allows reentrancy that can manipulate withdrawal state. \
                             External calls during withdrawal processing lack proper guards.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_fee_manipulation() {
            vulnerabilities.push(PartialWithdrawalGriefingVulnerability {
                location: loc,
                griefing_type: PartialWithdrawalGriefingType::WithdrawalFeeManipulation,
                severity: "High".to_string(),
                description: "Withdrawal fees can be manipulated to make partial withdrawals unprofitable. \
                             Dynamic fee calculation vulnerable to manipulation by privileged actors.".to_string(),
                confidence: 0.85,
            });
        }

        if let Some(loc) = self.detect_delay_attack() {
            vulnerabilities.push(PartialWithdrawalGriefingVulnerability {
                location: loc,
                griefing_type: PartialWithdrawalGriefingType::DelayAttackOnPartialWithdraw,
                severity: "Medium".to_string(),
                description: "Partial withdrawal delays can be artificially extended without bounds. \
                             Missing maximum delay caps allow indefinite griefing of withdrawals.".to_string(),
                confidence: 0.82,
            });
        }

        vulnerabilities
    }

    fn detect_queue_manipulation(&self) -> Option<usize> {
        // Queue operations without proper ordering/priority protection
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // Common withdraw selectors: 0x2e1a7d4d, 0x3ccfd60b
                if selector == 0x2e1a7d4d || selector == 0x3ccfd60b {
                    // Check for FIFO/priority enforcement
                    let mut has_ordering = false;
                    for j in i..std::cmp::min(i + 25, self.bytecode.len()) {
                        // Look for timestamp or nonce-based ordering
                        if self.bytecode[j] == 0x42 || // TIMESTAMP
                           (self.bytecode[j] == 0x54 && j > 0 && self.bytecode[j-1] == 0x60) // SLOAD with nonce
                        {
                            has_ordering = true;
                            break;
                        }
                    }
                    if !has_ordering {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_minimum_withdrawal_bypass(&self) -> Option<usize> {
        // Minimum withdrawal check with mutable parameter
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for withdrawal amount comparison
            if matches!(self.bytecode[i], 0x10 | 0x11 | 0x14) { // LT, GT, EQ
                // Check if comparing against mutable storage (minimum)
                let mut has_mutable_min = false;
                for j in i.saturating_sub(15)..i {
                    if self.bytecode[j] == 0x54 { // SLOAD (loading minimum)
                        // Check if this storage can be modified by admin
                        has_mutable_min = true;
                        break;
                    }
                }
                
                if has_mutable_min {
                    // Check if there's a cap on the minimum
                    let mut has_cap = false;
                    for j in i..std::cmp::min(i + 20, self.bytecode.len()) {
                        if matches!(self.bytecode[j], 0x10 | 0x11) { // LT or GT check on minimum
                            has_cap = true;
                            break;
                        }
                    }
                    if !has_cap {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_gas_griefing(&self) -> Option<usize> {
        // Unbounded loops in withdrawal processing
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x5b { // JUMPDEST (loop target)
                // Check for loop with withdrawal operations
                let mut has_sstore = false;
                let mut has_call = false;
                
                for j in i..std::cmp::min(i + 50, self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 { // SSTORE
                        has_sstore = true;
                    }
                    if self.bytecode[j] == 0xf1 { // CALL
                        has_call = true;
                    }
                    if self.bytecode[j] == 0x57 { // JUMPI (loop back)
                        break;
                    }
                }
                
                // Loop with state changes or calls without bound check
                if (has_sstore || has_call) {
                    // Check for iteration limit
                    let mut has_limit = false;
                    for j in i.saturating_sub(15)..i {
                        // Look for counter comparison
                        if matches!(self.bytecode[j], 0x10 | 0x11) { // LT or GT
                            has_limit = true;
                            break;
                        }
                    }
                    if !has_limit {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_reentrancy_during_withdrawal(&self) -> Option<usize> {
        // External call before state update in withdrawal
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xf1 { // CALL
                // Check if this is in withdrawal context
                let in_withdrawal_context = i > 50 && {
                    let mut found = false;
                    for j in i.saturating_sub(50)..i {
                        if self.bytecode[j] == 0x63 && j + 4 < self.bytecode.len() {
                            let sel = u32::from_be_bytes([
                                self.bytecode[j + 1],
                                self.bytecode[j + 2],
                                self.bytecode[j + 3],
                                self.bytecode[j + 4],
                            ]);
                            if sel == 0x2e1a7d4d || sel == 0x3ccfd60b { // withdraw selectors
                                found = true;
                                break;
                            }
                        }
                    }
                    found
                };
                
                if in_withdrawal_context {
                    // Check if SSTORE happens after CALL (checks-effects-interactions)
                    let mut has_sstore_after = false;
                    for j in i + 1..std::cmp::min(i + 20, self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // SSTORE after CALL
                            has_sstore_after = true;
                            break;
                        }
                    }
                    if has_sstore_after {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_fee_manipulation(&self) -> Option<usize> {
        // Dynamic withdrawal fee calculation without bounds
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for fee calculation (MUL with dynamic value)
            if self.bytecode[i] == 0x02 { // MUL
                // Check if multiplier comes from storage (dynamic fee)
                let mut has_storage_multiplier = false;
                for j in i.saturating_sub(10)..i {
                    if self.bytecode[j] == 0x54 { // SLOAD (fee parameter)
                        has_storage_multiplier = true;
                        break;
                    }
                }
                
                if has_storage_multiplier {
                    // Check for fee cap
                    let mut has_fee_cap = false;
                    for j in i..std::cmp::min(i + 25, self.bytecode.len()) {
                        if matches!(self.bytecode[j], 0x10 | 0x11) { // LT or GT (cap check)
                            has_fee_cap = true;
                            break;
                        }
                    }
                    if !has_fee_cap {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_delay_attack(&self) -> Option<usize> {
        // Withdrawal delay without maximum cap
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                // Check if used in delay calculation
                for j in i + 1..std::cmp::min(i + 20, self.bytecode.len()) {
                    if self.bytecode[j] == 0x01 { // ADD (adding delay)
                        // Check for maximum delay cap
                        let mut has_max_delay = false;
                        for k in j..std::cmp::min(j + 15, self.bytecode.len()) {
                            if matches!(self.bytecode[k], 0x10 | 0x11) { // LT or GT
                                has_max_delay = true;
                                break;
                            }
                        }
                        if !has_max_delay {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
