use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FeeMechanismType {
    ProtocolFeeBypass,
    RoyaltyCircumvention,
    FeeOnTransferAbuse,
    DynamicFeeManipulation,
    ZeroFeeExploit,
    FeeCalculationError,
    RoyaltyEnforcementWeakness,
    FeeSplitManipulation,
    RoundingErrorExploit,
    FeeReentrancy,
    AdminFeeAbuse,
    OperatorRoyaltyBypass,
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
pub struct FeeMechanismVulnerability {
    pub vulnerability_type: FeeMechanismType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct FeeMechanismAnalyzer {
    bytecode: Vec<u8>,
}

impl FeeMechanismAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<FeeMechanismVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_protocol_fee_bypass());
        vulnerabilities.extend(self.detect_royalty_circumvention());
        vulnerabilities.extend(self.detect_fee_on_transfer_abuse());
        vulnerabilities.extend(self.detect_dynamic_fee_manipulation());
        vulnerabilities.extend(self.detect_fee_calculation_errors());
        vulnerabilities.extend(self.detect_royalty_enforcement_weakness());

        vulnerabilities
    }

    fn detect_transfer_pattern(&self) -> bool {
        // Look for transfer functions
        let transfer_sigs = [
            &[0xa9, 0x05, 0x9c, 0xbb][..], // transfer(address,uint256)
            &[0x23, 0xb8, 0x72, 0xdd][..], // transferFrom(address,address,uint256)
            &[0xf2, 0x42, 0x43, 0x2a][..], // safeTransferFrom(address,address,uint256)
        ];

        transfer_sigs.iter().any(|&sig| {
            self.bytecode.windows(sig.len()).any(|w| w == sig)
        })
    }

    fn detect_protocol_fee_bypass(&self) -> Vec<FeeMechanismVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.detect_transfer_pattern() {
            return vulnerabilities;
        }

        // Look for transfer functions that should apply fees
        let transfer_sig = &[0xa9, 0x05, 0x9c, 0xbb][..]; // transfer()
        
        if let Some(pos) = self.bytecode.windows(transfer_sig.len()).position(|w| w == transfer_sig) {
            let function_section = &self.bytecode[pos..pos.saturating_add(150).min(self.bytecode.len())];
            
            // Check for fee calculation (MUL followed by DIV)
            let has_fee_calc = function_section.windows(3).any(|w| {
                w[0] == 0x02 && // MUL (amount * feeRate)
                w[1] == 0x04    // DIV (divide by denominator)
            });

            // Check if there's a way to skip fee
            let has_conditional_fee = function_section.windows(4).any(|w| {
                w[0] == 0x54 && // SLOAD (some flag)
                w[1] == 0x15 && // ISZERO
                w[2] == 0x57 && // JUMPI (skip fee if flag is set)
                has_fee_calc
            });

            if has_conditional_fee {
                // Check if the condition is properly protected
                let has_admin_check = function_section.windows(3).any(|w| {
                    w[0] == 0x33 && // CALLER
                    w[1] == 0x54 && // SLOAD (owner/admin)
                    w[2] == 0x14    // EQ
                });

                if !has_admin_check {
                    vulnerabilities.push(FeeMechanismVulnerability {
                        vulnerability_type: FeeMechanismType::ProtocolFeeBypass,
                        severity: SecuritySeverity::High,
                        location: pos,
                        description: "Protocol fee can be bypassed without proper access control".to_string(),
                        exploit_scenario: "Users can set flag or call function to skip protocol fees, draining revenue".to_string(),
                        remediation: "Ensure fee bypass conditions are only accessible by admin with proper checks".to_string(),
                    });
                }
            }

            // Check for zero amount transfers that might skip fees
            let has_zero_check = function_section.windows(2).any(|w| {
                w[0] == 0x15 && // ISZERO (check if amount == 0)
                w[1] == 0x57    // JUMPI
            });

            if !has_zero_check && has_fee_calc {
                vulnerabilities.push(FeeMechanismVulnerability {
                    vulnerability_type: FeeMechanismType::ZeroFeeExploit,
                    severity: SecuritySeverity::Low,
                    location: pos,
                    description: "Zero amount transfers not validated - potential fee calculation issues".to_string(),
                    exploit_scenario: "Zero transfers might bypass fee logic or cause unexpected behavior".to_string(),
                    remediation: "Add require(amount > 0) check before fee calculation".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn detect_royalty_circumvention(&self) -> Vec<FeeMechanismVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for NFT transfer functions
        let nft_transfer_sigs = [
            &[0x23, 0xb8, 0x72, 0xdd][..], // transferFrom()
            &[0x42, 0x84, 0x2e, 0x0e][..], // safeTransferFrom(address,address,uint256)
            &[0xb8, 0x8d, 0x4f, 0xde][..], // safeTransferFrom(address,address,uint256,bytes)
        ];

        for sig in &nft_transfer_sigs {
            if let Some(pos) = self.bytecode.windows(sig.len()).position(|w| w == *sig) {
                let function_section = &self.bytecode[pos..pos.saturating_add(100).min(self.bytecode.len())];
                
                // Check for ERC2981 royaltyInfo() call
                let royalty_info_sig = &[0x2a, 0x55, 0x20, 0x5a][..]; // royaltyInfo(uint256,uint256)
                let has_royalty_call = self.bytecode.windows(royalty_info_sig.len())
                    .any(|w| w == royalty_info_sig);

                // Check for external call to marketplace/royalty contract
                let has_external_royalty_check = function_section.contains(&0xfa) || // STATICCALL
                                                function_section.contains(&0xf1);    // CALL

                if !has_royalty_call && !has_external_royalty_check {
                    vulnerabilities.push(FeeMechanismVulnerability {
                        vulnerability_type: FeeMechanismType::RoyaltyCircumvention,
                        severity: SecuritySeverity::High,
                        location: pos,
                        description: "NFT transfer doesn't enforce ERC2981 royalty standard".to_string(),
                        exploit_scenario: "Users can transfer NFTs without paying creator royalties, bypassing revenue".to_string(),
                        remediation: "Implement ERC2981 and enforce royalty payments on all transfers or use operator filter".to_string(),
                    });
                }
            }
        }

        // Check for operator filter registry (OpenSea enforcement)
        let filter_registry_pattern = &[0x06, 0xfd, 0xde, 0x03][..]; // operatorFilterRegistry
        let has_operator_filter = self.bytecode.windows(filter_registry_pattern.len())
            .any(|w| w == filter_registry_pattern);

        if self.detect_nft_pattern() && !has_operator_filter {
            vulnerabilities.push(FeeMechanismVulnerability {
                vulnerability_type: FeeMechanismType::OperatorRoyaltyBypass,
                severity: SecuritySeverity::Medium,
                location: 0,
                description: "No operator filter registry - royalty enforcement can be bypassed".to_string(),
                exploit_scenario: "Unapproved marketplaces can facilitate zero-royalty trades".to_string(),
                remediation: "Integrate OpenSea's OperatorFilterRegistry to enforce royalty-respecting marketplaces".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_nft_pattern(&self) -> bool {
        let erc721_sig = &[0x63, 0x52, 0x21, 0x1e][..]; // ownerOf(uint256)
        self.bytecode.windows(erc721_sig.len()).any(|w| w == erc721_sig)
    }

    fn detect_fee_on_transfer_abuse(&self) -> Vec<FeeMechanismVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for tokens that take fees on transfer (reflection tokens, etc.)
        let transfer_sig = &[0xa9, 0x05, 0x9c, 0xbb][..]; // transfer()
        
        if let Some(pos) = self.bytecode.windows(transfer_sig.len()).position(|w| w == transfer_sig) {
            let function_section = &self.bytecode[pos..pos.saturating_add(120).min(self.bytecode.len())];
            
            // Check if transfer amount differs from received amount
            let has_fee_deduction = function_section.windows(4).any(|w| {
                w[0] == 0x02 && // MUL (calculate fee)
                w[1] == 0x04 && // DIV
                w[2] == 0x03    // SUB (deduct from amount)
            });

            if has_fee_deduction {
                // Check if the contract properly validates received vs sent amounts
                let has_balance_check = function_section.windows(4).any(|w| {
                    w[0] == 0x54 && // SLOAD (balance before)
                    w[1] == 0x54 && // SLOAD (balance after)
                    w[2] == 0x03 && // SUB (difference)
                    w[3] == 0x14    // EQ (verify amount)
                });

                if !has_balance_check {
                    vulnerabilities.push(FeeMechanismVulnerability {
                        vulnerability_type: FeeMechanismType::FeeOnTransferAbuse,
                        severity: SecuritySeverity::Medium,
                        location: pos,
                        description: "Fee-on-transfer token behavior not properly validated".to_string(),
                        exploit_scenario: "Contracts interacting with this token may incorrectly track balances".to_string(),
                        remediation: "Validate actual balance changes instead of transfer amounts".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_dynamic_fee_manipulation(&self) -> Vec<FeeMechanismVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for setFee() or updateFee() functions
        let set_fee_sigs = [
            &[0x69, 0xfe, 0x0e, 0x2d][..], // setFee(uint256)
            &[0x82, 0x65, 0xe5, 0x93][..], // updateFee(uint256)
        ];

        for sig in &set_fee_sigs {
            if let Some(pos) = self.bytecode.windows(sig.len()).position(|w| w == *sig) {
                let function_section = &self.bytecode[pos..pos.saturating_add(80).min(self.bytecode.len())];
                
                // Check for maximum fee cap
                let has_max_cap = function_section.windows(3).any(|w| {
                    w[0] == 0x10 && // LT (check fee < max)
                    w[1] == 0x15 && // ISZERO
                    w[2] == 0x57    // JUMPI (revert if too high)
                });

                if !has_max_cap {
                    vulnerabilities.push(FeeMechanismVulnerability {
                        vulnerability_type: FeeMechanismType::DynamicFeeManipulation,
                        severity: SecuritySeverity::Critical,
                        location: pos,
                        description: "Dynamic fee has no maximum cap - can be set to 100%".to_string(),
                        exploit_scenario: "Admin can set fee to 100% and steal all transferred funds (rug pull vector)".to_string(),
                        remediation: "Implement maximum fee cap (e.g., 5%) that cannot be exceeded".to_string(),
                    });
                }

                // Check for timelock on fee changes
                let has_timelock = function_section.windows(5).any(|w| {
                    w[0] == 0x42 && // TIMESTAMP
                    w[1] == 0x01 && // ADD (current time + delay)
                    w[2] == 0x55    // SSTORE (store future activation time)
                });

                if !has_timelock {
                    vulnerabilities.push(FeeMechanismVulnerability {
                        vulnerability_type: FeeMechanismType::AdminFeeAbuse,
                        severity: SecuritySeverity::High,
                        location: pos,
                        description: "Fee changes take effect immediately without timelock".to_string(),
                        exploit_scenario: "Admin can front-run large transactions by changing fee just before execution".to_string(),
                        remediation: "Implement timelock (e.g., 24-48 hours) before fee changes take effect".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_fee_calculation_errors(&self) -> Vec<FeeMechanismVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for fee calculation patterns
        if let Some(pos) = self.bytecode.windows(10).position(|w| {
            w.contains(&0x02) && // MUL
            w.contains(&0x04)    // DIV (percentage calculation)
        }) {
            let calc_section = &self.bytecode[pos..pos.saturating_add(15).min(self.bytecode.len())];
            
            // Check for proper rounding (should round down to avoid giving more than intended)
            // In Solidity, division automatically rounds down, but check for correct order
            let mul_pos = calc_section.iter().position(|&b| b == 0x02);
            let div_pos = calc_section.iter().position(|&b| b == 0x04);

            if let (Some(mul), Some(div)) = (mul_pos, div_pos) {
                // Correct order: MUL then DIV (to minimize rounding errors)
                if div < mul {
                    vulnerabilities.push(FeeMechanismVulnerability {
                        vulnerability_type: FeeMechanismType::RoundingErrorExploit,
                        severity: SecuritySeverity::Medium,
                        location: pos,
                        description: "Fee calculation order causes precision loss".to_string(),
                        exploit_scenario: "Incorrect operation order leads to rounding errors favoring users".to_string(),
                        remediation: "Always multiply before dividing: (amount * feeRate) / feeDenominator".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_royalty_enforcement_weakness(&self) -> Vec<FeeMechanismVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for ERC2981 implementation
        let royalty_info_sig = &[0x2a, 0x55, 0x20, 0x5a][..]; // royaltyInfo()
        
        if let Some(pos) = self.bytecode.windows(royalty_info_sig.len()).position(|w| w == royalty_info_sig) {
            let function_section = &self.bytecode[pos..pos.saturating_add(80).min(self.bytecode.len())];
            
            // Check if royalty can be set to zero
            let validates_nonzero = function_section.windows(3).any(|w| {
                w[0] == 0x15 && // ISZERO (check if zero)
                w[1] == 0x15 && // ISZERO (negate)
                w[2] == 0x57    // JUMPI (require non-zero)
            });

            if !validates_nonzero {
                vulnerabilities.push(FeeMechanismVulnerability {
                    vulnerability_type: FeeMechanismType::RoyaltyEnforcementWeakness,
                    severity: SecuritySeverity::Medium,
                    location: pos,
                    description: "Royalty can be set to zero - no enforcement".to_string(),
                    exploit_scenario: "Creator royalties can be completely disabled, bypassing revenue".to_string(),
                    remediation: "Enforce minimum royalty percentage (e.g., 2.5%) that cannot be disabled".to_string(),
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
    fn test_detect_transfer_pattern() {
        let bytecode = vec![
            0xa9, 0x05, 0x9c, 0xbb, // transfer() signature
        ];
        
        let analyzer = FeeMechanismAnalyzer::new(bytecode);
        assert!(analyzer.detect_transfer_pattern());
    }

    #[test]
    fn test_protocol_fee_bypass() {
        let bytecode = vec![
            0xa9, 0x05, 0x9c, 0xbb, // transfer()
            0x54, // SLOAD
            0x15, // ISZERO
            0x57, // JUMPI (conditional fee skip)
            0x02, // MUL
            0x04, // DIV (fee calc)
        ];
        
        let analyzer = FeeMechanismAnalyzer::new(bytecode);
        let vulns = analyzer.detect_protocol_fee_bypass();
        assert!(!vulns.is_empty());
    }

    #[test]
    fn test_dynamic_fee_manipulation() {
        let bytecode = vec![
            0x69, 0xfe, 0x0e, 0x2d, // setFee()
            0x55, // SSTORE (no max cap check)
        ];
        
        let analyzer = FeeMechanismAnalyzer::new(bytecode);
        let vulns = analyzer.detect_dynamic_fee_manipulation();
        assert!(!vulns.is_empty());
    }
}
