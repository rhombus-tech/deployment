use serde::{Serialize, Deserialize};

/// Donation Attack Detection (Euler Finance $200M exploit pattern)
/// 
/// Attack mechanism:
/// 1. Attacker donates assets directly to a vault/pool (bypassing deposit logic)
/// 2. This inflates totalAssets without minting shares
/// 3. Share price calculation becomes manipulated
/// 4. Subsequent depositors get fewer shares than they should
/// 5. Attacker can profit from the price manipulation
/// 
/// Common in: ERC-4626 vaults, lending protocols, yield aggregators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DonationAttackAdvancedVulnerability {
    /// Critical: Direct donation increases share price
    DirectDonationInflation {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// Critical: donateToReserves or similar function
    ExplicitDonationFunction {
        description: String,
        location: usize,
        function_selector: String,
    },
    /// High: totalAssets calculation vulnerable
    VulnerableTotalAssets {
        description: String,
        location: usize,
    },
    /// High: Missing minimum shares requirement
    NoMinimumShares {
        description: String,
        location: usize,
    },
    /// Medium: Balance-based calculations
    BalanceBasedAccounting {
        description: String,
        location: usize,
    },
}

pub struct DonationAttackAdvancedDetector {
    bytecode: Vec<u8>,
}

impl DonationAttackAdvancedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DonationAttackAdvancedVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Look for "donateToReserves" function (Euler-style)
        // Function selector: 0xe5d1c1d6 for donateToReserves
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x63 { // PUSH4 (function selector)
                if i + 4 < self.bytecode.len() {
                    let selector = u32::from_be_bytes([
                        self.bytecode[i+1],
                        self.bytecode[i+2],
                        self.bytecode[i+3],
                        self.bytecode[i+4],
                    ]);
                    
                    // Check for known dangerous function selectors
                    if selector == 0xe5d1c1d6 { // donateToReserves
                        vulnerabilities.push(DonationAttackAdvancedVulnerability::ExplicitDonationFunction {
                            description: "donateToReserves function found - direct Euler-style donation attack vector".to_string(),
                            location: i,
                            function_selector: format!("0x{:08x}", selector),
                        });
                    }
                }
            }
        }
        
        // Pattern 2: Check for share price calculation based on balance
        // Vulnerable pattern: shares = amount * totalSupply / totalAssets
        // where totalAssets = balanceOf(this)
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for BALANCE opcode (0x31)
            if self.bytecode[i] == 0x31 { // BALANCE
                // Check if this is used in a division (share calculation)
                let mut has_division = false;
                let mut has_multiplication = false;
                
                for j in i..std::cmp::min(i+30, self.bytecode.len()) {
                    if self.bytecode[j] == 0x04 { // DIV
                        has_division = true;
                    }
                    if self.bytecode[j] == 0x02 { // MUL
                        has_multiplication = true;
                    }
                }
                
                // If BALANCE is used in share price calculation
                if has_division && has_multiplication {
                    vulnerabilities.push(DonationAttackAdvancedVulnerability::VulnerableTotalAssets {
                        description: "Share price calculation uses BALANCE - vulnerable to donation inflation".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Pattern 3: Look for ERC20 balanceOf(address(this)) pattern
        // PUSH20 (address), PUSH4 (balanceOf selector), CALL
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // balanceOf selector: 0x70a08231
            if i + 4 < self.bytecode.len() &&
               self.bytecode[i] == 0x63 && // PUSH4
               self.bytecode[i+1] == 0x70 &&
               self.bytecode[i+2] == 0xa0 &&
               self.bytecode[i+3] == 0x82 &&
               self.bytecode[i+4] == 0x31 {  // balanceOf selector
                
                // Check if it's balanceOf(this)
                let mut is_self_balance = false;
                for j in i..std::cmp::min(i+20, self.bytecode.len()) {
                    if self.bytecode[j] == 0x30 { // ADDRESS (this contract)
                        is_self_balance = true;
                        break;
                    }
                }
                
                if is_self_balance {
                    // Now check if this is used in share calculation
                    let uses_in_division = self.bytecode[i..std::cmp::min(i+40, self.bytecode.len())]
                        .windows(2)
                        .any(|w| w[0] == 0x04 || w[0] == 0x02); // DIV or MUL
                    
                    if uses_in_division {
                        vulnerabilities.push(DonationAttackAdvancedVulnerability::BalanceBasedAccounting {
                            description: "totalAssets calculated via balanceOf(this) - donation attack possible".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        // Pattern 4: Check for missing minimum shares requirement
        // ERC-4626 vulnerability: first depositor should mint minimum shares
        // Look for deposit/mint functions without DEAD_SHARES check
        for i in 0..self.bytecode.len().saturating_sub(50) {
            // Look for mint function pattern
            if self.bytecode[i] == 0x63 { // PUSH4
                if i + 4 < self.bytecode.len() {
                    let selector = u32::from_be_bytes([
                        self.bytecode[i+1],
                        self.bytecode[i+2],
                        self.bytecode[i+3],
                        self.bytecode[i+4],
                    ]);
                    
                    // deposit(uint256,address): 0x6e553f65
                    // mint(uint256,address): 0x94bf804d
                    if selector == 0x6e553f65 || selector == 0x94bf804d {
                        // Check if there's a minimum shares check nearby
                        let has_minimum_check = self.bytecode[i..std::cmp::min(i+50, self.bytecode.len())]
                            .windows(3)
                            .any(|w| {
                                // Look for: PUSH (small value), GT/LT (comparison)
                                (w[0] == 0x60 && w[1] < 0x10 && (w[2] == 0x10 || w[2] == 0x11))
                            });
                        
                        if !has_minimum_check {
                            vulnerabilities.push(DonationAttackAdvancedVulnerability::NoMinimumShares {
                                description: format!(
                                    "Deposit/mint function (0x{:08x}) without minimum shares requirement - first depositor attack possible",
                                    selector
                                ),
                                location: i,
                            });
                        }
                    }
                }
            }
        }
        
        // Pattern 5: Check for convertToShares implementation
        // convertToShares selector: 0xc6e6f592
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.bytecode[i] == 0x63 &&
               i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i+1],
                    self.bytecode[i+2],
                    self.bytecode[i+3],
                    self.bytecode[i+4],
                ]);
                
                if selector == 0xc6e6f592 { // convertToShares
                    // Check if implementation has rounding protection
                    let has_rounding_protection = self.bytecode[i..std::cmp::min(i+60, self.bytecode.len())]
                        .windows(2)
                        .any(|w| {
                            // Look for ADD after DIV (rounding up)
                            w[0] == 0x04 && w[1] == 0x01
                        });
                    
                    if !has_rounding_protection {
                        vulnerabilities.push(DonationAttackAdvancedVulnerability::DirectDonationInflation {
                            description: "convertToShares without rounding protection - donation can inflate share price".to_string(),
                            location: i,
                            confidence: 0.80,
                        });
                    }
                }
            }
        }
        
        // Pattern 6: Detect virtual shares pattern (protection mechanism)
        let has_virtual_shares = self.detect_virtual_shares_protection();
        
        if !has_virtual_shares && vulnerabilities.len() > 0 {
            // If we found other vulnerabilities but no virtual shares protection
            vulnerabilities.push(DonationAttackAdvancedVulnerability::DirectDonationInflation {
                description: "No virtual shares/offset protection detected - vulnerable to donation inflation".to_string(),
                location: 0,
                confidence: 0.70,
            });
        }
        
        vulnerabilities
    }
    
    /// Check if contract implements virtual shares protection
    fn detect_virtual_shares_protection(&self) -> bool {
        // Virtual shares: totalSupply is offset by a constant (e.g., 1e8)
        // Look for constants being added to totalSupply
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            // Pattern: PUSH (large number), ADD (to totalSupply)
            if (self.bytecode[i] == 0x62 || // PUSH3
                self.bytecode[i] == 0x63 || // PUSH4
                self.bytecode[i] == 0x64) { // PUSH5
                
                // Check if followed by ADD and SLOAD (totalSupply)
                if i + 8 < self.bytecode.len() &&
                   self.bytecode[i+5] == 0x01 && // ADD
                   self.bytecode[i+6] == 0x54 {  // SLOAD
                    return true;
                }
            }
        }
        
        false
    }
}
