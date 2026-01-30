use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComptrollerBorrowedTokenReentrancyVulnerability {
    pub location: usize,
    pub reentrancy_type: ComptrollerReentrancyType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComptrollerReentrancyType {
    BorrowCallbackReentrancy,        // Reentrancy via borrow callback
    RedeemUnderlyingReentrancy,      // Reentrancy in redeem
    LiquidateReentrancy,             // Reentrancy in liquidation
    EnterMarketsReentrancy,          // Reentrancy in market entry
    ComptrollerStateMutation,        // State mutation during callback
    CollateralCheckBypass,           // Bypass collateral checks
}

pub struct ComptrollerBorrowedTokenReentrancyDetector {
    bytecode: Vec<u8>,
}

impl ComptrollerBorrowedTokenReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ComptrollerBorrowedTokenReentrancyVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_borrow_callback_reentrancy() {
            vulnerabilities.push(ComptrollerBorrowedTokenReentrancyVulnerability {
                location: loc,
                reentrancy_type: ComptrollerReentrancyType::BorrowCallbackReentrancy,
                severity: "Critical".to_string(),
                description: "Borrowed token callback enables reentrancy. Rari Fuse $80M exploit: attacker \
                             reentered via malicious token during borrow before state update. MUST update \
                             state before external token transfer.".to_string(),
                confidence: 0.95,
            });
        }

        if let Some(loc) = self.detect_redeem_reentrancy() {
            vulnerabilities.push(ComptrollerBorrowedTokenReentrancyVulnerability {
                location: loc,
                reentrancy_type: ComptrollerReentrancyType::RedeemUnderlyingReentrancy,
                severity: "Critical".to_string(),
                description: "Redeem function vulnerable to reentrancy via underlying token. External call \
                             before state finalization allows manipulation of redemption amounts.".to_string(),
                confidence: 0.92,
            });
        }

        if let Some(loc) = self.detect_liquidate_reentrancy() {
            vulnerabilities.push(ComptrollerBorrowedTokenReentrancyVulnerability {
                location: loc,
                reentrancy_type: ComptrollerReentrancyType::LiquidateReentrancy,
                severity: "High".to_string(),
                description: "Liquidation allows reentrancy during collateral seizure. Attacker can reenter \
                             to manipulate liquidation calculations or seize more collateral.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_enter_markets_reentrancy() {
            vulnerabilities.push(ComptrollerBorrowedTokenReentrancyVulnerability {
                location: loc,
                reentrancy_type: ComptrollerReentrancyType::EnterMarketsReentrancy,
                severity: "High".to_string(),
                description: "enterMarkets function has reentrancy risk. State changes after external calls \
                             to market tokens allow manipulation of market membership.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_comptroller_state_mutation() {
            vulnerabilities.push(ComptrollerBorrowedTokenReentrancyVulnerability {
                location: loc,
                reentrancy_type: ComptrollerReentrancyType::ComptrollerStateMutation,
                severity: "Critical".to_string(),
                description: "Comptroller state mutable during token callbacks. Allows changing collateral \
                             factors or market parameters mid-transaction to bypass checks.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_collateral_check_bypass() {
            vulnerabilities.push(ComptrollerBorrowedTokenReentrancyVulnerability {
                location: loc,
                reentrancy_type: ComptrollerReentrancyType::CollateralCheckBypass,
                severity: "Critical".to_string(),
                description: "Collateral checks bypassable via reentrancy. State inconsistency during callback \
                             allows borrowing beyond collateral limits.".to_string(),
                confidence: 0.90,
            });
        }

        vulnerabilities
    }

    fn detect_borrow_callback_reentrancy(&self) -> Option<usize> {
        // External call before SSTORE in borrow
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // borrow (0xc5ebeaec), borrowBehalf (0x2608f818)
                if selector == 0xc5ebeaec || selector == 0x2608f818 {
                    // Look for CALL before SSTORE
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        if self.bytecode[j] == 0xf1 { // CALL
                            // Check if SSTORE after
                            for k in j + 1..std::cmp::min(j + 15, self.bytecode.len()) {
                                if self.bytecode[k] == 0x55 { // SSTORE after CALL
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

    fn detect_redeem_reentrancy(&self) -> Option<usize> {
        // redeem/redeemUnderlying with external call before state update
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // redeem (0xdb006a75), redeemUnderlying (0x852a12e3)
                if selector == 0xdb006a75 || selector == 0x852a12e3 {
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        if self.bytecode[j] == 0xf1 {
                            for k in j + 1..std::cmp::min(j + 15, self.bytecode.len()) {
                                if self.bytecode[k] == 0x55 {
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

    fn detect_liquidate_reentrancy(&self) -> Option<usize> {
        // liquidateBorrow with reentrancy
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // liquidateBorrow (0xf5e3c462)
                if selector == 0xf5e3c462 {
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        if self.bytecode[j] == 0xf1 {
                            for k in j + 1..std::cmp::min(j + 15, self.bytecode.len()) {
                                if self.bytecode[k] == 0x55 {
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

    fn detect_enter_markets_reentrancy(&self) -> Option<usize> {
        // enterMarkets with external calls
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // enterMarkets (0xc2998238)
                if selector == 0xc2998238 {
                    let mut has_external_call = false;
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        if matches!(self.bytecode[j], 0xf1 | 0xfa) {
                            has_external_call = true;
                            break;
                        }
                    }
                    if has_external_call {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_comptroller_state_mutation(&self) -> Option<usize> {
        // SSTORE in comptroller during potential callback
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check if in callback-vulnerable function
                let in_vulnerable_context = i > 50 && {
                    let mut found = false;
                    for j in i.saturating_sub(50)..i {
                        if self.bytecode[j] == 0x63 && j + 4 < self.bytecode.len() {
                            let sel = u32::from_be_bytes([
                                self.bytecode[j + 1],
                                self.bytecode[j + 2],
                                self.bytecode[j + 3],
                                self.bytecode[j + 4],
                            ]);
                            if sel == 0xc5ebeaec || sel == 0xdb006a75 {
                                found = true;
                                break;
                            }
                        }
                    }
                    found
                };
                
                if in_vulnerable_context {
                    // Check if after external call
                    let mut has_prior_call = false;
                    for j in i.saturating_sub(20)..i {
                        if self.bytecode[j] == 0xf1 {
                            has_prior_call = true;
                            break;
                        }
                    }
                    if has_prior_call {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_collateral_check_bypass(&self) -> Option<usize> {
        // Collateral factor check after external call
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0xf1 { // CALL
                // Check if followed by collateral check (comparison)
                for j in i + 1..std::cmp::min(i + 35, self.bytecode.len()) {
                    if matches!(self.bytecode[j], 0x10 | 0x11) { // LT or GT
                        // This is checking something after call (likely collateral)
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
