use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc2222FundsDistributionVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct Erc2222FundsDistributionDetector {
    bytecode: Vec<u8>,
}

impl Erc2222FundsDistributionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc2222FundsDistributionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // ERC-2222 defines funds distribution to token holders
        // Detect distribution manipulation
        if let Some(location) = self.has_distribution_manipulation() {
            vulnerabilities.push(Erc2222FundsDistributionVulnerability {
                vulnerability_type: "ERC-2222 Distribution Manipulation".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Funds distribution calculation without snapshot-based balances. Users can manipulate balances between distribution announcement and execution to claim excess funds. Implement snapshot mechanism.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect reentrancy in withdrawal
        if let Some(location) = self.has_withdrawal_reentrancy() {
            vulnerabilities.push(Erc2222FundsDistributionVulnerability {
                vulnerability_type: "ERC-2222 Withdrawal Reentrancy".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "withdrawableFundsOf() allows reentrancy during withdrawal. Attackers can recursively withdraw funds multiple times. Implement checks-effects-interactions pattern and reentrancy guard.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect rounding error exploitation
        if let Some(location) = self.has_rounding_error_risk() {
            vulnerabilities.push(Erc2222FundsDistributionVulnerability {
                vulnerability_type: "ERC-2222 Distribution Rounding Error".to_string(),
                location,
                severity: "High".to_string(),
                description: "Funds distribution using division without handling remainder. Dust amounts accumulate and can be exploited or lost. Implement proper rounding and remainder tracking.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect double withdrawal
        if let Some(location) = self.has_double_withdrawal_risk() {
            vulnerabilities.push(Erc2222FundsDistributionVulnerability {
                vulnerability_type: "ERC-2222 Double Withdrawal".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Withdrawal tracking insufficient to prevent double claims. Users could withdraw the same distribution multiple times. Track withdrawn amounts per user per distribution period.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_distribution_manipulation(&self) -> Option<usize> {
        // Pattern: Balance read (SLOAD) in distribution calculation without snapshot
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 { // SLOAD (reading balance)
                // Look for distribution calculation (MUL + DIV)
                let mut has_distribution_calc = false;
                
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 { // MUL (proportional calculation)
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x04 { // DIV
                                has_distribution_calc = true;
                                break;
                            }
                        }
                    }
                }
                
                if has_distribution_calc {
                    // Check for snapshot mechanism (stored historical balance)
                    let mut has_snapshot = false;
                    for j in i.saturating_sub(20)..i {
                        // Look for block number or timestamp in storage key
                        if self.bytecode[j] == 0x43 || self.bytecode[j] == 0x42 { // NUMBER or TIMESTAMP
                            has_snapshot = true;
                        }
                    }
                    if !has_snapshot {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_withdrawal_reentrancy(&self) -> Option<usize> {
        // Pattern: External call (CALL) before state update (SSTORE)
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xf1 { // CALL (withdrawal transfer)
                // Check if state is updated after call (unsafe pattern)
                for j in i+1..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 { // SSTORE after CALL
                        // This is vulnerable - state updated after external call
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_rounding_error_risk(&self) -> Option<usize> {
        // Pattern: Division in distribution without remainder handling
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x04 { // DIV (distribution calculation)
                // Check if remainder is tracked (MOD operation)
                let mut has_remainder_tracking = false;
                
                for j in i+1..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x06 { // MOD (tracking remainder)
                        has_remainder_tracking = true;
                        break;
                    }
                }
                
                if !has_remainder_tracking {
                    // Verify this is distribution-related (followed by SSTORE or CALL)
                    for j in i+1..i+15.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 || self.bytecode[j] == 0xf1 { // SSTORE or CALL
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_double_withdrawal_risk(&self) -> Option<usize> {
        // Pattern: CALL (withdrawal) without prior SLOAD to check claimed status
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xf1 { // CALL (withdrawal)
                // Look for withdrawal tracking check before CALL
                let mut has_tracking_check = false;
                
                for j in i.saturating_sub(25)..i {
                    if self.bytecode[j] == 0x54 { // SLOAD (checking withdrawn status)
                        // Check if followed by ISZERO (must not be claimed)
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 { // ISZERO
                                has_tracking_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_tracking_check {
                    // Check if SSTORE happens after (marking as withdrawn)
                    for j in i+1..i+20.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // SSTORE (should happen but check wasn't before)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
