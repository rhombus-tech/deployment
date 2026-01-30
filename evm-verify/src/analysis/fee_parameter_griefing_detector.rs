use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeParameterGriefingVulnerability {
    pub location: usize,
    pub griefing_type: FeeGriefingType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeeGriefingType {
    UnboundedFeeIncrease,            // Protocol fees can be set arbitrarily high
    FeeManipulationDuringOperation,  // Change fees mid-operation to grief users
    AsymmetricFeeStructure,          // Fees favor protocol at user expense
    FeeExtractionWithoutCap,         // Extract fees without maximum limit
    DynamicFeeExploitation,          // Exploit dynamic fee mechanisms
    EmergencyFeeBypass,              // Bypass fees during emergency actions
}

pub struct FeeParameterGriefingDetector {
    bytecode: Vec<u8>,
}

impl FeeParameterGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<FeeParameterGriefingVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_unbounded_fee_increase() {
            vulnerabilities.push(FeeParameterGriefingVulnerability {
                location: loc,
                griefing_type: FeeGriefingType::UnboundedFeeIncrease,
                severity: "Critical".to_string(),
                description: "Protocol fees can be increased without upper bound. Admin or governance \
                             can set fees to 100% effectively confiscating user funds. Missing maximum \
                             fee cap allows complete griefing.".to_string(),
                confidence: 0.93,
            });
        }

        if let Some(loc) = self.detect_mid_operation_fee_change() {
            vulnerabilities.push(FeeParameterGriefingVulnerability {
                location: loc,
                griefing_type: FeeGriefingType::FeeManipulationDuringOperation,
                severity: "High".to_string(),
                description: "Fee parameters can be changed during active operations. Allows front-running \
                             user transactions with fee increases, griefing users who calculated costs \
                             based on old fees.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_asymmetric_fee_structure() {
            vulnerabilities.push(FeeParameterGriefingVulnerability {
                location: loc,
                griefing_type: FeeGriefingType::AsymmetricFeeStructure,
                severity: "Medium".to_string(),
                description: "Fee structure is asymmetric with no corresponding benefit to users. Protocol \
                             can extract value through fees without providing proportional service or \
                             without allowing user exit.".to_string(),
                confidence: 0.84,
            });
        }

        if let Some(loc) = self.detect_fee_extraction_without_cap() {
            vulnerabilities.push(FeeParameterGriefingVulnerability {
                location: loc,
                griefing_type: FeeGriefingType::FeeExtractionWithoutCap,
                severity: "High".to_string(),
                description: "Fee extraction mechanism lacks percentage or absolute caps. Fees calculated \
                             as percentage of principal without sanity checks, enabling effective fund \
                             confiscation.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_dynamic_fee_exploitation() {
            vulnerabilities.push(FeeParameterGriefingVulnerability {
                location: loc,
                griefing_type: FeeGriefingType::DynamicFeeExploitation,
                severity: "High".to_string(),
                description: "Dynamic fee mechanism can be exploited to inflate fees. Market conditions \
                             or oracle inputs used to calculate fees without proper bounds, allowing \
                             manipulation.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_emergency_fee_bypass() {
            vulnerabilities.push(FeeParameterGriefingVulnerability {
                location: loc,
                griefing_type: FeeGriefingType::EmergencyFeeBypass,
                severity: "Medium".to_string(),
                description: "Emergency functions can bypass normal fee caps. Privileged actors can invoke \
                             emergency mode to circumvent fee protections and extract excessive fees.".to_string(),
                confidence: 0.82,
            });
        }

        vulnerabilities
    }

    fn detect_unbounded_fee_increase(&self) -> Option<usize> {
        // Fee setter without maximum cap check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // Common fee setter selectors: setFee (0x69fe0e2d), setProtocolFee (0x787dce3d)
                if selector == 0x69fe0e2d || selector == 0x787dce3d {
                    // Check for maximum fee validation
                    let mut has_max_check = false;
                    for j in i..std::cmp::min(i + 25, self.bytecode.len()) {
                        if matches!(self.bytecode[j], 0x10 | 0x11) { // LT or GT
                            // Check if comparing against a constant (max fee)
                            for k in j.saturating_sub(5)..j {
                                if matches!(self.bytecode[k], 0x60..=0x7f) { // PUSH
                                    has_max_check = true;
                                    break;
                                }
                            }
                            if has_max_check {
                                break;
                            }
                        }
                    }
                    if !has_max_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_mid_operation_fee_change(&self) -> Option<usize> {
        // Fee parameter change without operation freeze
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Look for fee update SSTORE
            if self.bytecode[i] == 0x55 { // SSTORE (writing fee)
                // Check if there's an operation-in-progress check
                let mut has_reentrancy_guard = false;
                let mut has_pause_check = false;
                
                for j in i.saturating_sub(30)..i {
                    // Look for reentrancy guard or pause flag
                    if self.bytecode[j] == 0x54 { // SLOAD
                        // Check if followed by ISZERO (checking if not paused/locked)
                        if j + 1 < self.bytecode.len() && self.bytecode[j + 1] == 0x15 {
                            has_reentrancy_guard = true;
                            break;
                        }
                    }
                }
                
                // Fee SSTORE in admin function without proper guards
                if !has_reentrancy_guard && self.is_fee_related_storage(i) {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_asymmetric_fee_structure(&self) -> Option<usize> {
        // Fees on withdraw without corresponding benefit
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // Withdraw selector: 0x2e1a7d4d
                if selector == 0x2e1a7d4d {
                    // Check for fee calculation (MUL/DIV)
                    let mut has_fee = false;
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        if self.bytecode[j] == 0x02 || self.bytecode[j] == 0x04 { // MUL or DIV
                            has_fee = true;
                            break;
                        }
                    }
                    
                    if has_fee {
                        // Check if there's any fee bypass for long-term users
                        let mut has_bypass = false;
                        for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                            if self.bytecode[j] == 0x42 { // TIMESTAMP (time-based reduction)
                                has_bypass = true;
                                break;
                            }
                        }
                        if !has_bypass {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_fee_extraction_without_cap(&self) -> Option<usize> {
        // Fee calculation without percentage cap
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x02 { // MUL (fee calculation)
                // Check if this is percentage-based fee
                let mut is_percentage_fee = false;
                for j in i + 1..std::cmp::min(i + 5, self.bytecode.len()) {
                    if self.bytecode[j] == 0x04 { // DIV (by 10000 for percentage)
                        is_percentage_fee = true;
                        break;
                    }
                }
                
                if is_percentage_fee {
                    // Check if fee percentage has upper bound
                    let mut has_cap = false;
                    for j in i.saturating_sub(15)..i {
                        if matches!(self.bytecode[j], 0x10 | 0x11) { // LT or GT
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

    fn detect_dynamic_fee_exploitation(&self) -> Option<usize> {
        // Oracle-based fee without bounds
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for external call to oracle
            if self.bytecode[i] == 0xfa { // STATICCALL (oracle query)
                // Check if result is used in fee calculation
                for j in i + 1..std::cmp::min(i + 25, self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 { // MUL (using oracle data in fee)
                        // Check for sanity bounds on oracle value
                        let mut has_bounds = false;
                        for k in j..std::cmp::min(j + 15, self.bytecode.len()) {
                            if matches!(self.bytecode[k], 0x10 | 0x11) { // LT or GT
                                has_bounds = true;
                                break;
                            }
                        }
                        if !has_bounds {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_emergency_fee_bypass(&self) -> Option<usize> {
        // Emergency function with different fee logic
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // Emergency withdraw: 0xdb2e21bc, emergencyExit: 0xa433e58b
                if selector == 0xdb2e21bc || selector == 0xa433e58b {
                    // Check if fees are calculated differently
                    let mut has_different_fee = false;
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        if self.bytecode[j] == 0x02 { // MUL (fee calculation)
                            // Check if using different fee parameter
                            for k in j.saturating_sub(10)..j {
                                if self.bytecode[k] == 0x54 { // SLOAD (loading fee)
                                    has_different_fee = true;
                                    break;
                                }
                            }
                            if has_different_fee {
                                break;
                            }
                        }
                    }
                    
                    if has_different_fee {
                        // Check if emergency fee is capped
                        let mut has_emergency_cap = false;
                        for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                            if matches!(self.bytecode[j], 0x10 | 0x11) {
                                has_emergency_cap = true;
                                break;
                            }
                        }
                        if !has_emergency_cap {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn is_fee_related_storage(&self, sstore_pos: usize) -> bool {
        // Check if SSTORE is writing to fee-related storage slot
        // Look backwards for the slot being written
        for i in (sstore_pos.saturating_sub(35)..sstore_pos).rev() {
            if matches!(self.bytecode[i], 0x60..=0x7f) { // PUSH (slot)
                // Check if followed by storage operations indicating fee storage
                return true;
            }
        }
        false
    }
}
