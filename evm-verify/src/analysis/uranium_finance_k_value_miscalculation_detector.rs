use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UraniumFinanceKValueVulnerability {
    pub location: usize,
    pub k_value_type: KValueMiscalculationType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KValueMiscalculationType {
    IncorrectKFormula,               // K = x * y formula wrong
    MigrationKValueCorruption,       // K corrupted during migration
    SwapKValueViolation,             // Swap doesn't maintain K
    FeeCalculationError,             // Fee calculated incorrectly
    ReserveUpdateTiming,             // Reserves updated at wrong time
    IntegerOverflowInK,              // Overflow in K calculation
}

pub struct UraniumFinanceKValueMiscalculationDetector {
    bytecode: Vec<u8>,
}

impl UraniumFinanceKValueMiscalculationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<UraniumFinanceKValueVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_incorrect_k_formula() {
            vulnerabilities.push(UraniumFinanceKValueVulnerability {
                location: loc,
                k_value_type: KValueMiscalculationType::IncorrectKFormula,
                severity: "Critical".to_string(),
                description: "AMM K=x*y invariant formula incorrect. Uranium Finance $50M exploit: migration \
                             bug allowed withdrawing more than deposited. K MUST equal reserve0 * reserve1 \
                             after fees, checked before and after swaps.".to_string(),
                confidence: 0.95,
            });
        }

        if let Some(loc) = self.detect_migration_k_corruption() {
            vulnerabilities.push(UraniumFinanceKValueVulnerability {
                location: loc,
                k_value_type: KValueMiscalculationType::MigrationKValueCorruption,
                severity: "Critical".to_string(),
                description: "Pool migration corrupts K value. Transfer of liquidity between pools doesn't \
                             preserve constant product invariant, allowing value extraction.".to_string(),
                confidence: 0.93,
            });
        }

        if let Some(loc) = self.detect_swap_k_violation() {
            vulnerabilities.push(UraniumFinanceKValueVulnerability {
                location: loc,
                k_value_type: KValueMiscalculationType::SwapKValueViolation,
                severity: "Critical".to_string(),
                description: "Swap function doesn't maintain K invariant. Reserve updates allow K to decrease, \
                             enabling draining pool through repeated swaps.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_fee_calculation_error() {
            vulnerabilities.push(UraniumFinanceKValueVulnerability {
                location: loc,
                k_value_type: KValueMiscalculationType::FeeCalculationError,
                severity: "High".to_string(),
                description: "Fee calculation allows K invariant violation. Incorrect fee application enables \
                             arbitrage that extracts value without compensating LPs.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_reserve_update_timing() {
            vulnerabilities.push(UraniumFinanceKValueVulnerability {
                location: loc,
                k_value_type: KValueMiscalculationType::ReserveUpdateTiming,
                severity: "High".to_string(),
                description: "Reserves updated before K check. Timing allows temporary K violation during \
                             transaction execution, enabling manipulation.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_integer_overflow_in_k() {
            vulnerabilities.push(UraniumFinanceKValueVulnerability {
                location: loc,
                k_value_type: KValueMiscalculationType::IntegerOverflowInK,
                severity: "Critical".to_string(),
                description: "K value calculation vulnerable to integer overflow. Large reserve values cause \
                             overflow, wrapping K to small value and breaking invariant.".to_string(),
                confidence: 0.90,
            });
        }

        vulnerabilities
    }

    fn detect_incorrect_k_formula(&self) -> Option<usize> {
        // MUL without proper K validation
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x02 { // MUL (K = reserve0 * reserve1)
                // Check if this is in swap context
                let in_swap = i > 50 && {
                    let mut found = false;
                    for j in i.saturating_sub(50)..i {
                        if self.bytecode[j] == 0x63 && j + 4 < self.bytecode.len() {
                            let sel = u32::from_be_bytes([
                                self.bytecode[j + 1],
                                self.bytecode[j + 2],
                                self.bytecode[j + 3],
                                self.bytecode[j + 4],
                            ]);
                            if sel == 0x022c0d9f { // swap
                                found = true;
                                break;
                            }
                        }
                    }
                    found
                };
                
                if in_swap {
                    // Check for K >= previous K check
                    let mut has_k_check = false;
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        if matches!(self.bytecode[j], 0x10 | 0x11) { // LT or GT
                            has_k_check = true;
                            break;
                        }
                    }
                    if !has_k_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_migration_k_corruption(&self) -> Option<usize> {
        // Migration function without K preservation
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // migrate (0xce5494bb), migrateLiquidity (0x8f283970)
                if selector == 0xce5494bb || selector == 0x8f283970 {
                    // Check for K validation (MUL followed by comparison)
                    let mut has_k_validation = false;
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        if self.bytecode[j] == 0x02 {
                            for k in j..std::cmp::min(j + 15, self.bytecode.len()) {
                                if matches!(self.bytecode[k], 0x10 | 0x11 | 0x14) {
                                    has_k_validation = true;
                                    break;
                                }
                            }
                            if has_k_validation {
                                break;
                            }
                        }
                    }
                    if !has_k_validation {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_swap_k_violation(&self) -> Option<usize> {
        // Swap with SSTORE before K check
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                if selector == 0x022c0d9f { // swap
                    // Check order: should be calculation, check, then SSTORE
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // SSTORE (updating reserves)
                            // Check if K verified before SSTORE
                            let mut has_prior_k_check = false;
                            for k in i..j {
                                if self.bytecode[k] == 0x02 { // MUL (K calc)
                                    for m in k..j {
                                        if matches!(self.bytecode[m], 0x10 | 0x11) {
                                            has_prior_k_check = true;
                                            break;
                                        }
                                    }
                                    if has_prior_k_check {
                                        break;
                                    }
                                }
                            }
                            if !has_prior_k_check {
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_fee_calculation_error(&self) -> Option<usize> {
        // Fee calculation that doesn't preserve K
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // DIV or MUL for fee calculation
            if self.bytecode[i] == 0x04 || self.bytecode[i] == 0x02 {
                // Check if in swap context with fee
                let has_fee_calc = i > 30 && {
                    let mut found = false;
                    for j in i.saturating_sub(30)..i {
                        if matches!(self.bytecode[j], 0x60..=0x7f) {
                            // Check for fee constant (e.g., 997, 9970)
                            if j + 2 < self.bytecode.len() {
                                let val = u16::from_be_bytes([self.bytecode[j + 1], self.bytecode[j + 2]]);
                                if val == 997 || val == 9970 || val == 30 {
                                    found = true;
                                    break;
                                }
                            }
                        }
                    }
                    found
                };
                
                if has_fee_calc {
                    // Check if K validated after fee
                    let mut has_k_check_after = false;
                    for j in i..std::cmp::min(i + 25, self.bytecode.len()) {
                        if matches!(self.bytecode[j], 0x10 | 0x11) {
                            has_k_check_after = true;
                            break;
                        }
                    }
                    if !has_k_check_after {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_reserve_update_timing(&self) -> Option<usize> {
        // SSTORE before K calculation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check if MUL (K calc) happens after
                for j in i + 1..std::cmp::min(i + 25, self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 { // MUL
                        // K calculated after reserve update - wrong order
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_integer_overflow_in_k(&self) -> Option<usize> {
        // MUL without overflow check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x02 { // MUL
                // Check for overflow protection (comparison or revert)
                let mut has_overflow_check = false;
                for j in i..std::cmp::min(i + 25, self.bytecode.len()) {
                    // Look for DIV to verify (if a*b/b != a, overflow occurred)
                    if self.bytecode[j] == 0x04 {
                        for k in j..std::cmp::min(j + 10, self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 { // EQ
                                has_overflow_check = true;
                                break;
                            }
                        }
                        if has_overflow_check {
                            break;
                        }
                    }
                }
                if !has_overflow_check {
                    return Some(i);
                }
            }
        }
        None
    }
}
