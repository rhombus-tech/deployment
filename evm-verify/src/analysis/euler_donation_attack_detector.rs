use serde::{Serialize, Deserialize};

/// Euler Finance Donation Attack Detection ($197M March 2023)
/// 
/// The Euler hack exploited a vulnerability where:
/// 1. Attacker takes a flash loan
/// 2. Deposits collateral to borrow maximum
/// 3. Donates tokens to their own account to manipulate health factor
/// 4. The protocol's health check uses donated balance instead of actual collateral
/// 5. Attacker can borrow more than they should, draining the protocol
///
/// Key patterns:
/// - Direct token transfers that affect health calculations
/// - Health factor checks that use balanceOf() instead of internal accounting
/// - Donation followed by liquidation or withdrawal
/// - Missing checks for donated vs deposited amounts

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EulerDonationVulnerability {
    /// Critical: Health factor calculation uses balanceOf() which can be manipulated
    HealthFactorManipulation {
        description: String,
        location: usize,
        confidence: f32,
    },
    
    /// Critical: Direct token transfer affects collateral calculation
    DonationAffectsCollateral {
        description: String,
        location: usize,
        confidence: f32,
    },
    
    /// High: Liquidation or withdrawal without internal balance tracking
    MissingInternalAccounting {
        description: String,
        location: usize,
        confidence: f32,
    },
    
    /// High: Health check doesn't differentiate donated vs deposited tokens
    NoDonationProtection {
        description: String,
        location: usize,
        confidence: f32,
    },
}

pub struct EulerDonationAttackDetector {
    bytecode: Vec<u8>,
}

impl EulerDonationAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<EulerDonationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Health factor calculation using balanceOf()
        vulnerabilities.extend(self.detect_balance_based_health_checks());
        
        // Pattern 2: Direct transfers affecting collateral
        vulnerabilities.extend(self.detect_donation_collateral_manipulation());
        
        // Pattern 3: Missing internal accounting
        vulnerabilities.extend(self.detect_missing_internal_tracking());
        
        // Pattern 4: Liquidation without donation checks
        vulnerabilities.extend(self.detect_unprotected_liquidation());
        
        vulnerabilities
    }
    
    fn detect_balance_based_health_checks(&self) -> Vec<EulerDonationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Look for health check functions that call balanceOf()
        let balance_of_sig = &[0x70, 0xa0, 0x82, 0x31]; // balanceOf(address)
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            // Look for pattern: STATICCALL to balanceOf followed by division/comparison
            if i + 50 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 50];
                
                // Check if this looks like a health factor calculation
                let has_balance_of = section.windows(4).any(|w| w == balance_of_sig);
                let has_division = section.contains(&0x04); // DIV
                let has_comparison = section.contains(&0x10) || section.contains(&0x12); // LT or SLT
                
                if has_balance_of && has_division && has_comparison {
                    // Check if there's no internal balance check (SLOAD before balanceOf)
                    let has_internal_check = section[..20].contains(&0x54); // SLOAD
                    
                    if !has_internal_check {
                        vulnerabilities.push(EulerDonationVulnerability::HealthFactorManipulation {
                            description: format!(
                                "Health factor calculation at PC {} uses balanceOf() without internal accounting. \
                                This is the EXACT pattern exploited in Euler Finance ($197M). \
                                An attacker can donate tokens to manipulate their health factor and over-borrow.",
                                i
                            ),
                            location: i,
                            confidence: 0.95,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn detect_donation_collateral_manipulation(&self) -> Vec<EulerDonationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Look for patterns where external transfers affect collateral calculations
        // Pattern: balanceOf() result used in collateral/borrow calculations
        
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if i + 150 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 150];
                
                // Look for: balanceOf call → arithmetic → borrow/collateral function
                let balance_call_pos = section.windows(4)
                    .position(|w| w == &[0x70, 0xa0, 0x82, 0x31]);
                
                if let Some(pos) = balance_call_pos {
                    let after_balance = &section[pos..];
                    
                    // Check if balance is used in multiplication/division (collateral calc)
                    let check_len = std::cmp::min(30, after_balance.len());
                    let has_collateral_calc = after_balance[..check_len].contains(&0x02) || // MUL
                                             after_balance[..check_len].contains(&0x04);   // DIV
                    
                    // Check for borrow function signatures
                    let has_borrow = after_balance.windows(4).any(|w| {
                        w == &[0xc5, 0xec, 0xd0, 0x4c] || // borrow()
                        w == &[0xa4, 0x15, 0xbc, 0xad]    // mint()
                    });
                    
                    if has_collateral_calc && has_borrow {
                        vulnerabilities.push(EulerDonationVulnerability::DonationAffectsCollateral {
                            description: format!(
                                "Collateral calculation at PC {} uses balanceOf() result directly. \
                                Attacker can donate tokens to increase their perceived collateral \
                                and borrow more than allowed (Euler attack pattern).",
                                i + pos
                            ),
                            location: i + pos,
                            confidence: 0.92,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn detect_missing_internal_tracking(&self) -> Vec<EulerDonationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Look for deposit/withdraw functions that don't update internal balances
        let deposit_sigs = [
            &[0xb6, 0xb5, 0x5f, 0x25][..], // deposit(uint256,address)
            &[0xe2, 0xbf, 0xb4, 0xa0][..], // supply(address,uint256,address,uint16)
        ];
        
        for sig in &deposit_sigs {
            for i in 0..self.bytecode.len().saturating_sub(4) {
                if &self.bytecode[i..i + 4] == *sig {
                    // Found deposit function, check if it updates internal state
                    let func_section = &self.bytecode[i..std::cmp::min(i + 200, self.bytecode.len())];
                    
                    // Check for SSTORE (internal balance update)
                    let has_state_update = func_section.contains(&0x55); // SSTORE
                    
                    // Check for only balanceOf() calls
                    let has_balance_of = func_section.windows(4)
                        .any(|w| w == &[0x70, 0xa0, 0x82, 0x31]);
                    
                    if has_balance_of && !has_state_update {
                        vulnerabilities.push(EulerDonationVulnerability::MissingInternalAccounting {
                            description: format!(
                                "Deposit function at PC {} relies on balanceOf() without maintaining \
                                internal balance tracking. This allows donation attacks where external \
                                transfers manipulate the protocol's view of user balances.",
                                i
                            ),
                            location: i,
                            confidence: 0.88,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn detect_unprotected_liquidation(&self) -> Vec<EulerDonationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Look for liquidation functions that don't check for donation manipulation
        let liquidate_sig = &[0x5b, 0x51, 0x95, 0x0f]; // liquidate() or similar
        
        for i in 0..self.bytecode.len().saturating_sub(4) {
            if i + 150 < self.bytecode.len() && &self.bytecode[i..i + 4] == liquidate_sig {
                let func_section = &self.bytecode[i..i + 150];
                
                // Check if liquidation uses balanceOf() for health check
                let uses_balance_of = func_section.windows(4)
                    .any(|w| w == &[0x70, 0xa0, 0x82, 0x31]);
                
                // Check for donation protection (comparing internal vs external balance)
                let has_donation_check = func_section.windows(10).any(|w| {
                    // Pattern: SLOAD (internal) → STATICCALL (balanceOf) → SUB → ISZERO
                    w.contains(&0x54) && w.contains(&0xFA) && w.contains(&0x03) && w.contains(&0x15)
                });
                
                if uses_balance_of && !has_donation_check {
                    vulnerabilities.push(EulerDonationVulnerability::NoDonationProtection {
                        description: format!(
                            "Liquidation function at PC {} doesn't protect against donation attacks. \
                            The Euler attacker donated tokens to manipulate health factors before liquidation. \
                            Should compare internal accounting with actual balanceOf() to detect manipulation.",
                            i
                        ),
                        location: i,
                        confidence: 0.85,
                    });
                }
            }
        }
        
        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_euler_vulnerable_pattern() {
        // Simulate vulnerable bytecode: balanceOf() → DIV → LT (no SLOAD)
        let bytecode = vec![
            0x70, 0xa0, 0x82, 0x31, // balanceOf()
            0x00, 0x00, 0x00, 0x00,
            0x04, // DIV
            0x10, // LT
            0x57, // JUMPI
        ];
        
        let detector = EulerDonationAttackDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty(), "Should detect Euler-style vulnerability");
    }
    
    #[test]
    fn test_safe_internal_accounting() {
        // Simulate safe bytecode: SLOAD → balanceOf() → comparison
        let bytecode = vec![
            0x54, // SLOAD (internal balance)
            0x70, 0xa0, 0x82, 0x31, // balanceOf()
            0x03, // SUB (compare)
            0x15, // ISZERO
            0x04, // DIV
            0x10, // LT
        ];
        
        let detector = EulerDonationAttackDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        // Should have fewer vulnerabilities due to internal accounting
        assert!(vulns.len() < 2, "Should recognize internal accounting as safer");
    }
}
