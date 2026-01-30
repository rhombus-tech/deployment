use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundlerBundleStuffingVulnerability {
    pub location: usize,
    pub vulnerability_type: BundleStuffingType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BundleStuffingType {
    ProfitableUserOpReplacement,     // Bundler replaces user ops with own
    FrontRunningInsertion,           // Bundler front-runs user operations
    GasPriceManipulation,            // Manipulate gas to favor own ops
    SelectiveInclusion,              // Cherry-pick profitable ops only
    MEVExtraction,                   // Extract MEV from user operations
    BundlePriorityManipulation,      // Manipulate bundle ordering
}

pub struct BundlerBundleStuffingDetector {
    bytecode: Vec<u8>,
}

impl BundlerBundleStuffingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BundlerBundleStuffingVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_profitable_replacement() {
            vulnerabilities.push(BundlerBundleStuffingVulnerability {
                location: loc,
                vulnerability_type: BundleStuffingType::ProfitableUserOpReplacement,
                severity: "Critical".to_string(),
                description: "Bundler can replace user operations with own operations that extract \
                             more value. No reputation penalty for dropping user ops after simulation.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_frontrunning_insertion() {
            vulnerabilities.push(BundlerBundleStuffingVulnerability {
                location: loc,
                vulnerability_type: BundleStuffingType::FrontRunningInsertion,
                severity: "High".to_string(),
                description: "Bundler can insert own UserOps before user operations to front-run \
                             profitable transactions without penalty.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_gas_price_manipulation() {
            vulnerabilities.push(BundlerBundleStuffingVulnerability {
                location: loc,
                vulnerability_type: BundleStuffingType::GasPriceManipulation,
                severity: "Medium".to_string(),
                description: "Gas price handling allows bundler to manipulate pricing to favor \
                             inclusion of own operations over user operations.".to_string(),
                confidence: 0.84,
            });
        }

        if let Some(loc) = self.detect_selective_inclusion() {
            vulnerabilities.push(BundlerBundleStuffingVulnerability {
                location: loc,
                vulnerability_type: BundleStuffingType::SelectiveInclusion,
                severity: "High".to_string(),
                description: "Bundler can selectively include only profitable operations and censor \
                             unprofitable user operations without reputation impact.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_mev_extraction() {
            vulnerabilities.push(BundlerBundleStuffingVulnerability {
                location: loc,
                vulnerability_type: BundleStuffingType::MEVExtraction,
                severity: "Critical".to_string(),
                description: "Bundler can extract MEV from user operations by reordering or \
                             inserting operations without proper user compensation.".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.detect_priority_manipulation() {
            vulnerabilities.push(BundlerBundleStuffingVulnerability {
                location: loc,
                vulnerability_type: BundleStuffingType::BundlePriorityManipulation,
                severity: "High".to_string(),
                description: "Bundle priority can be manipulated to favor bundler's own operations \
                             over user operations in execution order.".to_string(),
                confidence: 0.87,
            });
        }

        vulnerabilities
    }

    fn detect_profitable_replacement(&self) -> Option<usize> {
        // handleOps without proper user op validation
        // Pattern: PUSH4(handleOps selector) without subsequent CALLER check
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                // handleOps selector: 0x1fad948c
                if selector == 0x1fad948c {
                    let mut has_caller_check = false;
                    for j in i..std::cmp::min(i + 15, self.bytecode.len()) {
                        if self.bytecode[j] == 0x33 { // CALLER
                            has_caller_check = true;
                            break;
                        }
                    }
                    if !has_caller_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_frontrunning_insertion(&self) -> Option<usize> {
        // UserOp array manipulation without validation
        // Pattern: CALLDATALOAD followed by array manipulation without signature check
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x35 { // CALLDATALOAD
                let mut has_sig_check = false;
                for j in i..std::cmp::min(i + 12, self.bytecode.len()) {
                    // Look for STATICCALL to signature verification
                    if self.bytecode[j] == 0xfa { // STATICCALL
                        has_sig_check = true;
                        break;
                    }
                }
                if !has_sig_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_gas_price_manipulation(&self) -> Option<usize> {
        // maxFeePerGas/maxPriorityFeePerGas handling without validation
        for i in 0..self.bytecode.len().saturating_sub(12) {
            if self.bytecode[i] == 0x3a { // GASPRICE
                // Check if compared with user-provided value
                let mut has_comparison = false;
                for j in i + 1..std::cmp::min(i + 10, self.bytecode.len()) {
                    if matches!(self.bytecode[j], 0x10 | 0x11 | 0x14) { // LT, GT, EQ
                        has_comparison = true;
                        break;
                    }
                }
                if !has_comparison {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_selective_inclusion(&self) -> Option<usize> {
        // Bundle submission without mandatory inclusion enforcement
        // Pattern: CALL to EntryPoint without revert on failure
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0xf1 { // CALL
                // Check if result is checked
                if i + 3 < self.bytecode.len() {
                    if self.bytecode[i + 1] != 0x15 && // Not followed by ISZERO
                       self.bytecode[i + 2] != 0xfd    // Not followed by REVERT
                    {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_mev_extraction(&self) -> Option<usize> {
        // DEX interaction within bundler code (sandwich opportunity)
        // Pattern: SWAP selector followed by value transfer
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                // Common swap selectors: 0x38ed1739, 0x7ff36ab5
                if selector == 0x38ed1739 || selector == 0x7ff36ab5 {
                    // Check for value transfer nearby
                    for j in i..std::cmp::min(i + 25, self.bytecode.len()) {
                        if matches!(self.bytecode[j], 0x60..=0x7f) { // PUSH with value
                            if j + 2 < self.bytecode.len() && self.bytecode[j + 2] == 0xf1 { // CALL
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_priority_manipulation(&self) -> Option<usize> {
        // Priority fee distribution without user consent
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for coinbase transfer (miner tip)
            if self.bytecode[i] == 0x41 { // COINBASE
                for j in i..std::cmp::min(i + 15, self.bytecode.len()) {
                    if self.bytecode[j] == 0xf1 || self.bytecode[j] == 0xf4 { // CALL or DELEGATECALL
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
