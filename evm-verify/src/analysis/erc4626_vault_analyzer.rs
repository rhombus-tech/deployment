use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VaultVulnerabilityType {
    SharePriceManipulation,
    InflationAttack,
    FirstDepositorExploit,
    RoundingError,
    WithdrawReentrancy,
    AssetRecoveryIssue,
    PreviewFunctionMismatch,
    MaxDepositBypass,
    FeeManipulation,
    VirtualSharesWeakness,
    DecimalMismatch,
    TotalAssetsManipulation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultVulnerability {
    pub vulnerability_type: VaultVulnerabilityType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct ERC4626VaultAnalyzer {
    bytecode: Vec<u8>,
}

impl ERC4626VaultAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<VaultVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_inflation_attack());
        vulnerabilities.extend(self.detect_first_depositor_exploit());
        vulnerabilities.extend(self.detect_rounding_errors());
        vulnerabilities.extend(self.detect_share_price_manipulation());
        vulnerabilities.extend(self.detect_preview_function_issues());
        vulnerabilities.extend(self.detect_total_assets_manipulation());

        vulnerabilities
    }

    fn detect_vault_pattern(&self) -> bool {
        // Look for ERC4626 function signatures
        let vault_sigs = [
            &[0x38, 0xd5, 0x2e, 0x0f][..], // asset()
            &[0x01, 0xe1, 0xd1, 0x14][..], // totalAssets()
            &[0x07, 0xa2, 0xd1, 0x3a][..], // convertToShares(uint256)
            &[0xc6, 0xe6, 0xf5, 0x92][..], // convertToAssets(uint256)
        ];

        vault_sigs.iter().filter(|&&sig| {
            self.bytecode.windows(sig.len()).any(|w| w == sig)
        }).count() >= 2
    }

    fn detect_inflation_attack(&self) -> Vec<VaultVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.detect_vault_pattern() {
            return vulnerabilities;
        }

        // Inflation attack: attacker deposits 1 wei, then donates large amount to manipulate share price
        // Look for deposit() function
        let deposit_sig = &[0xb6, 0xb5, 0x5f, 0x25][..]; // deposit(uint256,address)
        
        if let Some(pos) = self.bytecode.windows(deposit_sig.len()).position(|w| w == deposit_sig) {
            let function_section = &self.bytecode[pos..pos.saturating_add(120).min(self.bytecode.len())];
            
            // Check for minimum deposit amount
            let has_min_deposit = function_section.windows(3).any(|w| {
                w[0] == 0x10 && // LT (check amount >= minimum)
                w[1] == 0x15 && // ISZERO
                w[2] == 0x57    // JUMPI (revert if below minimum)
            });

            if !has_min_deposit {
                vulnerabilities.push(VaultVulnerability {
                    vulnerability_type: VaultVulnerabilityType::InflationAttack,
                    severity: SecuritySeverity::Critical,
                    location: pos,
                    description: "Vault vulnerable to inflation attack - no minimum deposit".to_string(),
                    exploit_scenario: "Attacker deposits 1 wei, donates large amount directly to vault, manipulates share price to steal from next depositor".to_string(),
                    remediation: "Implement minimum deposit amount (e.g., 1e4) and/or virtual shares offset (ERC4626 extension)".to_string(),
                });
            }

            // Check for virtual shares/offset implementation
            let has_virtual_shares = self.bytecode.windows(4).any(|w| {
                // Look for addition of offset in share calculation
                w.contains(&0x01) && // ADD
                w.contains(&0x02) && // MUL
                w.contains(&0x04)    // DIV (share calc with offset)
            });

            if !has_virtual_shares && !has_min_deposit {
                vulnerabilities.push(VaultVulnerability {
                    vulnerability_type: VaultVulnerabilityType::VirtualSharesWeakness,
                    severity: SecuritySeverity::High,
                    location: pos,
                    description: "No virtual shares offset - vulnerable to precision attacks".to_string(),
                    exploit_scenario: "Share price can be manipulated through donation attacks".to_string(),
                    remediation: "Implement virtual shares offset as per OpenZeppelin ERC4626 implementation".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn detect_first_depositor_exploit(&self) -> Vec<VaultVulnerability> {
        let mut vulnerabilities = Vec::new();

        // First depositor can grief by depositing 1 wei and donating to inflate share price
        let total_supply_sig = &[0x18, 0x16, 0x0d, 0xdd][..]; // totalSupply()
        let total_assets_sig = &[0x01, 0xe1, 0xd1, 0x14][..]; // totalAssets()
        
        if let Some(pos) = self.bytecode.windows(total_assets_sig.len()).position(|w| w == total_assets_sig) {
            let function_section = &self.bytecode[pos..pos.saturating_add(100).min(self.bytecode.len())];
            
            // Check if totalSupply() is checked for zero
            let checks_supply_zero = function_section.windows(3).any(|w| {
                w[0] == 0x54 && // SLOAD (totalSupply)
                w[1] == 0x15 && // ISZERO
                w[2] == 0x57    // JUMPI (special handling for first deposit)
            });

            if !checks_supply_zero {
                vulnerabilities.push(VaultVulnerability {
                    vulnerability_type: VaultVulnerabilityType::FirstDepositorExploit,
                    severity: SecuritySeverity::High,
                    location: pos,
                    description: "First depositor exploit - no special handling for initial deposit".to_string(),
                    exploit_scenario: "First depositor deposits 1 wei, then donates assets to inflate price before second deposit".to_string(),
                    remediation: "Mint dead shares to address(0) or vault itself on first deposit to prevent manipulation".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn detect_rounding_errors(&self) -> Vec<VaultVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for convertToShares and convertToAssets functions
        let convert_to_shares_sig = &[0x07, 0xa2, 0xd1, 0x3a][..]; // convertToShares()
        let convert_to_assets_sig = &[0xc6, 0xe6, 0xf5, 0x92][..]; // convertToAssets()
        
        for sig in &[convert_to_shares_sig, convert_to_assets_sig] {
            if let Some(pos) = self.bytecode.windows(sig.len()).position(|w| w == *sig) {
                let function_section = &self.bytecode[pos..pos.saturating_add(50).min(self.bytecode.len())];
                
                // Check for proper rounding direction
                // convertToShares should round DOWN (favor vault)
                // convertToAssets should round DOWN (favor vault)
                let mul_pos = function_section.iter().position(|&b| b == 0x02); // MUL
                let div_pos = function_section.iter().position(|&b| b == 0x04); // DIV

                if let (Some(mul), Some(div)) = (mul_pos, div_pos) {
                    // Correct order: MUL before DIV
                    if div < mul {
                        vulnerabilities.push(VaultVulnerability {
                            vulnerability_type: VaultVulnerabilityType::RoundingError,
                            severity: SecuritySeverity::Medium,
                            location: pos,
                            description: "Conversion function has incorrect operation order".to_string(),
                            exploit_scenario: "Rounding errors favor users over vault, leading to gradual asset drain".to_string(),
                            remediation: "Use correct order: (amount * totalShares) / totalAssets, not (amount / totalAssets) * totalShares".to_string(),
                        });
                    }
                }

                // Check if there's a zero division check
                let has_zero_check = function_section.windows(3).any(|w| {
                    w[0] == 0x15 && // ISZERO (check denominator)
                    w[1] == 0x15 && // ISZERO (negate)
                    w[2] == 0x57    // JUMPI (revert if zero)
                });

                if !has_zero_check {
                    vulnerabilities.push(VaultVulnerability {
                        vulnerability_type: VaultVulnerabilityType::RoundingError,
                        severity: SecuritySeverity::High,
                        location: pos,
                        description: "Conversion function lacks zero division protection".to_string(),
                        exploit_scenario: "Division by zero when totalAssets or totalSupply is zero, causing contract to revert".to_string(),
                        remediation: "Add require(totalSupply > 0) before division operations".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_share_price_manipulation(&self) -> Vec<VaultVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for totalAssets() implementation
        let total_assets_sig = &[0x01, 0xe1, 0xd1, 0x14][..]; // totalAssets()
        
        if let Some(pos) = self.bytecode.windows(total_assets_sig.len()).position(|w| w == total_assets_sig) {
            let function_section = &self.bytecode[pos..pos.saturating_add(100).min(self.bytecode.len())];
            
            // Check if totalAssets() uses balanceOf(address(this))
            let uses_balance_of = function_section.windows(5).any(|w| {
                w.contains(&0x70) && // balanceOf selector prefix
                w.contains(&0x30)    // ADDRESS (address(this))
            });

            if uses_balance_of {
                // This is vulnerable to direct transfers inflating totalAssets
                vulnerabilities.push(VaultVulnerability {
                    vulnerability_type: VaultVulnerabilityType::SharePriceManipulation,
                    severity: SecuritySeverity::High,
                    location: pos,
                    description: "totalAssets() uses balanceOf - vulnerable to donation attacks".to_string(),
                    exploit_scenario: "Attacker directly transfers tokens to vault to manipulate share price and steal from depositors".to_string(),
                    remediation: "Track assets internally with accounting variables, not raw balanceOf(address(this))".to_string(),
                });
            }

            // Check for asset recovery mechanism
            let has_sweep = self.bytecode.windows(4).any(|w| {
                w == &[0x01, 0xd5, 0xd3, 0xec][..] // sweep() or similar
            });

            if uses_balance_of && !has_sweep {
                vulnerabilities.push(VaultVulnerability {
                    vulnerability_type: VaultVulnerabilityType::AssetRecoveryIssue,
                    severity: SecuritySeverity::Medium,
                    location: pos,
                    description: "No mechanism to recover accidentally sent tokens".to_string(),
                    exploit_scenario: "Donated/mistakenly sent tokens permanently affect share price with no recovery".to_string(),
                    remediation: "Implement sweep() function to recover excess tokens not tracked in accounting".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn detect_preview_function_issues(&self) -> Vec<VaultVulnerability> {
        let mut vulnerabilities = Vec::new();

        // ERC4626 requires preview functions match actual operations
        let preview_deposit_sig = &[0xef, 0x8b, 0x30, 0xf7][..]; // previewDeposit()
        let deposit_sig = &[0xb6, 0xb5, 0x5f, 0x25][..]; // deposit()
        
        let has_preview = self.bytecode.windows(preview_deposit_sig.len())
            .any(|w| w == preview_deposit_sig);
        let has_deposit = self.bytecode.windows(deposit_sig.len())
            .any(|w| w == deposit_sig);

        if has_deposit && !has_preview {
            vulnerabilities.push(VaultVulnerability {
                vulnerability_type: VaultVulnerabilityType::PreviewFunctionMismatch,
                severity: SecuritySeverity::Medium,
                location: 0,
                description: "Missing previewDeposit() function - ERC4626 non-compliant".to_string(),
                exploit_scenario: "Front-ends cannot accurately estimate share amounts, leading to user confusion and slippage".to_string(),
                remediation: "Implement all required ERC4626 preview functions that match actual operations".to_string(),
            });
        }

        // Check for maxDeposit() implementation
        let max_deposit_sig = &[0x40, 0x2d, 0x26, 0x7d][..]; // maxDeposit()
        
        if let Some(pos) = self.bytecode.windows(max_deposit_sig.len()).position(|w| w == max_deposit_sig) {
            let function_section = &self.bytecode[pos..pos.saturating_add(50).min(self.bytecode.len())];
            
            // Check if it returns a sensible value (not uint256.max always)
            let returns_max = function_section.windows(3).any(|w| {
                w[0] == 0x7f && // PUSH32
                w[1] == 0xff && // all 0xFF (uint256.max)
                w[2] == 0xff
            });

            if returns_max {
                vulnerabilities.push(VaultVulnerability {
                    vulnerability_type: VaultVulnerabilityType::MaxDepositBypass,
                    severity: SecuritySeverity::Low,
                    location: pos,
                    description: "maxDeposit() always returns uint256.max - no deposit limit".to_string(),
                    exploit_scenario: "Vault can be over-deposited beyond intended capacity".to_string(),
                    remediation: "Implement proper deposit limits based on strategy capacity".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn detect_total_assets_manipulation(&self) -> Vec<VaultVulnerability> {
        let mut vulnerabilities = Vec::new();

        let total_assets_sig = &[0x01, 0xe1, 0xd1, 0x14][..]; // totalAssets()
        
        if let Some(pos) = self.bytecode.windows(total_assets_sig.len()).position(|w| w == total_assets_sig) {
            let function_section = &self.bytecode[pos..pos.saturating_add(80).min(self.bytecode.len())];
            
            // Check for external calls in totalAssets (gas griefing vector)
            let has_external_call = function_section.contains(&0xf1) || // CALL
                                   function_section.contains(&0xfa) || // STATICCALL
                                   function_section.contains(&0xf2);   // CALLCODE

            if has_external_call {
                vulnerabilities.push(VaultVulnerability {
                    vulnerability_type: VaultVulnerabilityType::TotalAssetsManipulation,
                    severity: SecuritySeverity::Medium,
                    location: pos,
                    description: "totalAssets() makes external calls - gas griefing risk".to_string(),
                    exploit_scenario: "Malicious strategy can cause totalAssets() to consume excessive gas or revert, DOSing withdrawals".to_string(),
                    remediation: "Cache asset values or limit gas for external calls in view functions".to_string(),
                });
            }
        }

        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_vault_pattern() {
        let bytecode = vec![
            0x38, 0xd5, 0x2e, 0x0f, // asset()
            0x01, 0xe1, 0xd1, 0x14, // totalAssets()
        ];
        
        let analyzer = ERC4626VaultAnalyzer::new(bytecode);
        assert!(analyzer.detect_vault_pattern());
    }

    #[test]
    fn test_inflation_attack_detection() {
        let bytecode = vec![
            0x38, 0xd5, 0x2e, 0x0f, // asset()
            0x01, 0xe1, 0xd1, 0x14, // totalAssets()
            0xb6, 0xb5, 0x5f, 0x25, // deposit() without minimum check
        ];
        
        let analyzer = ERC4626VaultAnalyzer::new(bytecode);
        let vulns = analyzer.detect_inflation_attack();
        assert!(!vulns.is_empty());
    }

    #[test]
    fn test_rounding_error_detection() {
        let bytecode = vec![
            0x07, 0xa2, 0xd1, 0x3a, // convertToShares()
            0x04, // DIV before
            0x02, // MUL (wrong order)
        ];
        
        let analyzer = ERC4626VaultAnalyzer::new(bytecode);
        let vulns = analyzer.detect_rounding_errors();
        assert!(!vulns.is_empty());
    }
}
