use serde::{Serialize, Deserialize};

/// Vault Deposit Manipulation Detection (Gamma Strategies exploit pattern)
/// 
/// Attack mechanism:
/// 1. Attacker deposits small amount to mint initial shares
/// 2. Directly transfers large amount of underlying to vault (donation)
/// 3. Share price inflates dramatically
/// 4. Next depositor gets extremely few shares due to inflated price
/// 5. Attacker withdraws with profit
/// 
/// Different from donation attack: focuses on deposit flow manipulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultDepositManipulationVulnerability {
    /// Critical: First deposit can be manipulated
    FirstDepositorManipulation {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// Critical: Deposit function vulnerable to price manipulation
    DepositPriceManipulation {
        description: String,
        location: usize,
    },
    /// High: No dead shares or minimum deposit
    NoMinimumDeposit {
        description: String,
        location: usize,
    },
    /// High: Withdraw allows stealing inflated value
    WithdrawInflationExploit {
        description: String,
        location: usize,
    },
    /// Medium: Preview functions don't match actual execution
    PreviewMismatch {
        description: String,
        location: usize,
    },
}

pub struct VaultDepositManipulationDetector {
    bytecode: Vec<u8>,
}

impl VaultDepositManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<VaultDepositManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Check deposit function for first depositor protection
        // ERC-4626 deposit: 0x6e553f65
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i+1], self.bytecode[i+2],
                    self.bytecode[i+3], self.bytecode[i+4],
                ]);
                
                if selector == 0x6e553f65 { // deposit(uint256,address)
                    // Check for totalSupply == 0 branch
                    let has_zero_check = self.bytecode[i..std::cmp::min(i+80, self.bytecode.len())]
                        .windows(5)
                        .any(|w| {
                            // Pattern: SLOAD (totalSupply), ISZERO, JUMPI
                            w[0] == 0x54 && w[1] == 0x15 && w[2] == 0x57
                        });
                    
                    if !has_zero_check {
                        vulnerabilities.push(VaultDepositManipulationVulnerability::FirstDepositorManipulation {
                            description: "Deposit function lacks first depositor protection - price can be manipulated".to_string(),
                            location: i,
                            confidence: 0.85,
                        });
                    }
                    
                    // Check if deposit calculates shares correctly
                    let calculates_shares = self.bytecode[i..std::cmp::min(i+80, self.bytecode.len())]
                        .windows(3)
                        .any(|w| {
                            // MUL followed by DIV (share calculation)
                            w[0] == 0x02 && w[1] == 0x04
                        });
                    
                    if calculates_shares {
                        // Check for minimum shares check after calculation
                        let has_minimum = self.bytecode[i..std::cmp::min(i+80, self.bytecode.len())]
                            .windows(3)
                            .any(|w| {
                                // GT or LT with small value
                                (w[0] == 0x60 && w[1] < 0x64 && (w[2] == 0x10 || w[2] == 0x11))
                            });
                        
                        if !has_minimum {
                            vulnerabilities.push(VaultDepositManipulationVulnerability::DepositPriceManipulation {
                                description: "Share calculation without minimum check - vulnerable to inflation attack".to_string(),
                                location: i,
                            });
                        }
                    }
                }
            }
        }
        
        // Pattern 2: Check previewDeposit vs actual deposit consistency
        // previewDeposit: 0xef8b30f7
        // They should use the same calculation
        let preview_deposit_loc = self.find_function_selector(0xef8b30f7);
        let deposit_loc = self.find_function_selector(0x6e553f65);
        
        if let (Some(preview), Some(deposit)) = (preview_deposit_loc, deposit_loc) {
            // Check if both use similar calculation patterns
            let preview_has_mul_div = self.has_mul_div_pattern(preview, 60);
            let deposit_has_mul_div = self.has_mul_div_pattern(deposit, 80);
            
            if preview_has_mul_div != deposit_has_mul_div {
                vulnerabilities.push(VaultDepositManipulationVulnerability::PreviewMismatch {
                    description: "previewDeposit and deposit use different calculations - can be exploited".to_string(),
                    location: preview,
                });
            }
        }
        
        // Pattern 3: Check for "dead shares" pattern (Uniswap V2 style)
        // First mint should lock minimum liquidity
        let has_dead_shares = self.detect_dead_shares_pattern();
        
        if !has_dead_shares {
            // Look for any mint function
            for i in 0..self.bytecode.len().saturating_sub(40) {
                if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                    let selector = u32::from_be_bytes([
                        self.bytecode[i+1], self.bytecode[i+2],
                        self.bytecode[i+3], self.bytecode[i+4],
                    ]);
                    
                    // mint: 0x94bf804d or _mint internal
                    if selector == 0x94bf804d {
                        vulnerabilities.push(VaultDepositManipulationVulnerability::NoMinimumDeposit {
                            description: "No dead shares protection - first depositor can manipulate entire vault".to_string(),
                            location: i,
                        });
                        break;
                    }
                }
            }
        }
        
        // Pattern 4: Check withdraw/redeem for inflation exploitation
        // withdraw: 0xb460af94, redeem: 0xba087652
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i+1], self.bytecode[i+2],
                    self.bytecode[i+3], self.bytecode[i+4],
                ]);
                
                if selector == 0xb460af94 || selector == 0xba087652 {
                    // Check if withdraw uses inflated price without checks
                    let has_slippage = self.bytecode[i..std::cmp::min(i+60, self.bytecode.len())]
                        .windows(3)
                        .any(|w| {
                            // Look for GT/LT comparisons (slippage check)
                            w[0] == 0x10 || w[0] == 0x11
                        });
                    
                    if !has_slippage {
                        vulnerabilities.push(VaultDepositManipulationVulnerability::WithdrawInflationExploit {
                            description: "Withdraw/redeem without slippage protection - can extract inflated value".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        // Pattern 5: Check for totalAssets manipulation vulnerability
        // totalAssets should not be purely balance-based
        let total_assets_loc = self.find_function_selector(0x01e1d114); // totalAssets()
        
        if let Some(loc) = total_assets_loc {
            // Check if it uses BALANCE opcode directly
            let uses_balance_directly = self.bytecode[loc..std::cmp::min(loc+40, self.bytecode.len())]
                .iter()
                .any(|&b| b == 0x31); // BALANCE
            
            if uses_balance_directly {
                vulnerabilities.push(VaultDepositManipulationVulnerability::DepositPriceManipulation {
                    description: "totalAssets uses direct balance - vulnerable to donation manipulation".to_string(),
                    location: loc,
                });
            }
        }
        
        // Pattern 6: Look for convertToAssets and convertToShares
        // They should be consistent and protected
        let convert_to_assets = self.find_function_selector(0x07a2d13a);
        let convert_to_shares = self.find_function_selector(0xc6e6f592);
        
        if let (Some(assets_loc), Some(shares_loc)) = (convert_to_assets, convert_to_shares) {
            // Both should have overflow protection
            let assets_protected = self.has_overflow_check(assets_loc, 50);
            let shares_protected = self.has_overflow_check(shares_loc, 50);
            
            if !assets_protected || !shares_protected {
                vulnerabilities.push(VaultDepositManipulationVulnerability::FirstDepositorManipulation {
                    description: "Conversion functions lack overflow protection - manipulation possible".to_string(),
                    location: std::cmp::min(assets_loc, shares_loc),
                    confidence: 0.75,
                });
            }
        }
        
        vulnerabilities
    }
    
    fn find_function_selector(&self, selector: u32) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let found = u32::from_be_bytes([
                    self.bytecode[i+1], self.bytecode[i+2],
                    self.bytecode[i+3], self.bytecode[i+4],
                ]);
                if found == selector {
                    return Some(i);
                }
            }
        }
        None
    }
    
    fn has_mul_div_pattern(&self, start: usize, range: usize) -> bool {
        let end = std::cmp::min(start + range, self.bytecode.len());
        self.bytecode[start..end]
            .windows(3)
            .any(|w| w[0] == 0x02 && w[1] == 0x04) // MUL, DIV
    }
    
    fn has_overflow_check(&self, start: usize, range: usize) -> bool {
        let end = std::cmp::min(start + range, self.bytecode.len());
        self.bytecode[start..end]
            .windows(2)
            .any(|w| w[0] == 0x10 || w[0] == 0x11 || w[0] == 0x13) // LT, GT, or ISZERO
    }
    
    fn detect_dead_shares_pattern(&self) -> bool {
        // Look for MINIMUM_LIQUIDITY constant (1000 in Uni V2)
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x61 && i + 2 < self.bytecode.len() {
                // PUSH2 with value around 1000 (0x03e8)
                let value = u16::from_be_bytes([
                    self.bytecode[i+1],
                    self.bytecode[i+2],
                ]);
                if value >= 100 && value <= 10000 {
                    // Check if this is used in a mint context
                    let near_mint = self.bytecode[i..std::cmp::min(i+20, self.bytecode.len())]
                        .windows(2)
                        .any(|w| w[0] == 0x55); // SSTORE (minting)
                    if near_mint {
                        return true;
                    }
                }
            }
        }
        false
    }
}
