use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeBanditProfitabilityVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct TimeBanditProfitabilityDetector {
    bytecode: Vec<u8>,
}

impl TimeBanditProfitabilityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TimeBanditProfitabilityVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Time-bandit attacks involve deep reorgs to extract MEV
        // Detect high-value settlements without finality protection
        if let Some(location) = self.has_reorg_vulnerable_settlement() {
            vulnerabilities.push(TimeBanditProfitabilityVulnerability {
                vulnerability_type: "Time-Bandit Reorg Vulnerability".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Large value settlements finalize without sufficient block depth. Validators can profitably reorg chain to capture MEV exceeding block rewards. Require multi-block confirmation or finality gadgets before large transfers.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect block number dependency creating reorg incentive
        if let Some(location) = self.has_block_dependent_value_transfer() {
            vulnerabilities.push(TimeBanditProfitabilityVulnerability {
                vulnerability_type: "Block-Dependent Value Transfer Reorg Risk".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Value transfers depend on specific block numbers without reorg protection. Attackers can reorg to different block number for favorable outcomes. Use epoch-based finality or commit-reveal schemes.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect liquidations creating time-bandit incentive
        if let Some(location) = self.has_liquidation_reorg_incentive() {
            vulnerabilities.push(TimeBanditProfitabilityVulnerability {
                vulnerability_type: "Liquidation Time-Bandit Incentive".to_string(),
                location,
                severity: "High".to_string(),
                description: "Large liquidations settle immediately without finality protection. Liquidators can reorg chain to retry failed liquidations or extract additional MEV. Implement delayed settlement with finality checks.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_reorg_vulnerable_settlement(&self) -> Option<usize> {
        // Pattern: Large value transfer without block depth confirmation
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for value transfer
            if self.bytecode[i] == 0xf1 { // CALL (transfer)
                // Check if large value
                let mut is_large_value = false;
                
                for j in i.saturating_sub(25)..i {
                    // Look for value parameter (3rd parameter to CALL)
                    // Large value is typically loaded from storage or balance
                    if self.bytecode[j] == 0x47 || self.bytecode[j] == 0x31 { // SELFBALANCE or BALANCE
                        is_large_value = true;
                    }
                }
                
                if is_large_value {
                    // Check if there's finality protection (block depth check)
                    let mut has_finality_check = false;
                    
                    for j in i.saturating_sub(40)..i {
                        // Look for block number comparison (depth check)
                        if self.bytecode[j] == 0x43 { // NUMBER
                            for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x03 { // SUB (currentBlock - settlementBlock)
                                    // Check if compared to minimum depth
                                    for m in k+1..(k+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                                        if self.bytecode[m] == 0x10 || self.bytecode[m] == 0x11 { // LT/GT
                                            has_finality_check = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    if !has_finality_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_block_dependent_value_transfer(&self) -> Option<usize> {
        // Pattern: Transfer amount depends on block number
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x43 { // NUMBER
                // Check if block number affects transfer amount
                for j in i+1..i+35.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 || self.bytecode[j] == 0x04 { // MUL or DIV
                        // Check if result used in transfer
                        for k in j+1..(j+25).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0xf1 { // CALL (transfer)
                                // Verify no reorg protection (finality check)
                                let mut has_reorg_protection = false;
                                
                                for m in i.saturating_sub(30)..k {
                                    // Look for finality gadget or commitment
                                    if self.bytecode[m] == 0x40 { // BLOCKHASH (checking past blocks)
                                        has_reorg_protection = true;
                                    }
                                }
                                
                                if !has_reorg_protection {
                                    return Some(i);
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn has_liquidation_reorg_incentive(&self) -> Option<usize> {
        // Pattern: Liquidation without settlement delay
        for i in 0..self.bytecode.len().saturating_sub(50) {
            // Look for collateral transfer (liquidation)
            if self.bytecode[i] == 0xf1 { // CALL (transfer collateral)
                // Check if this is liquidation (health factor check before)
                let mut is_liquidation = false;
                
                for j in i.saturating_sub(45)..i {
                    // Look for health factor calculation (division, comparison)
                    if self.bytecode[j] == 0x04 { // DIV (collateral / debt)
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 { // LT (health < threshold)
                                is_liquidation = true;
                                break;
                            }
                        }
                    }
                }
                
                if is_liquidation {
                    // Check if settlement is immediate (no delay)
                    let mut has_settlement_delay = false;
                    
                    for j in i.saturating_sub(35)..i {
                        // Look for timestamp-based delay
                        if self.bytecode[j] == 0x42 { // TIMESTAMP
                            for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x01 { // ADD (timestamp + delay)
                                    has_settlement_delay = true;
                                    break;
                                }
                            }
                        }
                    }
                    
                    if !has_settlement_delay {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
