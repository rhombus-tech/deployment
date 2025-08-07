use std::collections::HashMap;
use anyhow::Result;
use crate::bytecode::{BytecodeAnalyzer, SecurityWarning};
use crate::bytecode::security::{SecurityWarningKind, SecuritySeverity};
use ethers::types::H160;
use std::str::FromStr;

/// Smart filtering system for context-aware vulnerability detection
#[derive(Debug)]
pub struct SmartFilter {
    /// Known safe contract addresses (major protocols)
    safe_contracts: Vec<H160>,
    /// Patterns indicating Solidity 0.8+ with built-in overflow protection
    modern_solidity_patterns: Vec<Vec<u8>>,
}

impl SmartFilter {
    pub fn new() -> Self {
        Self {
            safe_contracts: Self::init_safe_contracts(),
            modern_solidity_patterns: Self::init_modern_patterns(),
        }
    }
    
    /// Initialize list of known-safe major protocol addresses
    fn init_safe_contracts() -> Vec<H160> {
        vec![
            // Uniswap V2 Router
            H160::from_str("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D").unwrap(),
            // Uniswap V3 Router  
            H160::from_str("0xE592427A0AEce92De3Edee1F18E0157C05861564").unwrap(),
            // WETH9
            H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
            // Compound cUSDC
            H160::from_str("0x39AA39c021dfbaE8faC545936693aC917d5E7563").unwrap(),
            // Compound cETH
            H160::from_str("0x4Ddc2D193948926D02f9B1fE9e1daa0718270ED5").unwrap(),
            // OpenZeppelin Proxy patterns (common addresses)
            H160::from_str("0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24").unwrap(),
        ]
    }
    
    /// Bytecode patterns that indicate modern Solidity with built-in protections
    fn init_modern_patterns() -> Vec<Vec<u8>> {
        vec![
            // Solidity 0.8+ panic patterns (arithmetic overflow reverts)
            vec![0x4e, 0x48, 0x7b, 0x71], // Panic(0x11) for arithmetic overflow
            vec![0x08, 0xc3, 0x79, 0xa0], // Custom revert with selector
            // SafeMath library calls (older but safe)
            vec![0x63, 0x1e, 0x8c, 0x4c], // SafeMath.add selector
            vec![0x63, 0xa0, 0x69, 0x12], // SafeMath.sub selector
        ]
    }
    
    /// Check if contract address is in the known-safe list
    pub fn is_safe_contract(&self, address: Option<H160>) -> bool {
        if let Some(addr) = address {
            self.safe_contracts.contains(&addr)
        } else {
            false
        }
    }
    
    /// Check if bytecode indicates modern Solidity with built-in protections
    pub fn has_modern_protections(&self, bytecode: &[u8]) -> bool {
        for pattern in &self.modern_solidity_patterns {
            if self.contains_pattern(bytecode, pattern) {
                return true;
            }
        }
        false
    }
    
    /// Check if bytecode contains a specific pattern
    fn contains_pattern(&self, haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|window| window == needle)
    }
    
    /// Smart filter for arithmetic vulnerabilities
    pub fn filter_arithmetic_warnings(&self, 
        warnings: Vec<SecurityWarning>, 
        bytecode: &[u8], 
        contract_address: Option<H160>
    ) -> Vec<SecurityWarning> {
        // Skip arithmetic warnings for known-safe contracts or modern Solidity
        if self.is_safe_contract(contract_address) || self.has_modern_protections(bytecode) {
            warnings.into_iter()
                .filter(|w| !w.description.contains("overflow") && !w.description.contains("underflow"))
                .collect()
        } else {
            warnings // Keep all warnings for potentially vulnerable contracts
        }
    }
    
    /// Smart filter for access control warnings  
    pub fn filter_access_control_warnings(&self,
        warnings: Vec<SecurityWarning>,
        contract_address: Option<H160>
    ) -> Vec<SecurityWarning> {
        // Only skip access control warnings for major audited protocols
        if self.is_safe_contract(contract_address) {
            warnings.into_iter()
                .filter(|w| !w.description.contains("access control"))
                .collect()
        } else {
            warnings // Keep warnings for unknown contracts
        }
    }
    
    /// Smart filter for unchecked calls - keep HIGH severity only
    pub fn filter_unchecked_calls(&self, warnings: Vec<SecurityWarning>) -> Vec<SecurityWarning> {
        warnings.into_iter()
            .filter(|w| {
                if w.description.contains("unchecked") {
                    // Only keep high-severity unchecked calls
                    matches!(w.severity, crate::bytecode::security::SecuritySeverity::High)
                } else {
                    true
                }
            })
            .collect()
    }
    
    /// Smart filter for MEV warnings - context-aware detection
    pub fn filter_mev_warnings(&self, 
        warnings: Vec<SecurityWarning>, 
        contract_address: Option<H160>
    ) -> Vec<SecurityWarning> {
        warnings.into_iter()
            .filter(|w| {
                if w.description.contains("MEV") || w.description.contains("front-running") {
                    // Keep MEV warnings for unknown contracts but skip for major DEXs
                    !self.is_safe_contract(contract_address)
                } else {
                    true
                }
            })
            .collect()
    }
    
    /// Comprehensive smart filtering - the main entry point
    pub fn apply_smart_filtering(&self,
        mut warnings: Vec<SecurityWarning>,
        bytecode: &[u8],
        contract_address: Option<H160>
    ) -> Vec<SecurityWarning> {
        // Apply all smart filters
        warnings = self.filter_arithmetic_warnings(warnings, bytecode, contract_address);
        warnings = self.filter_access_control_warnings(warnings, contract_address);
        warnings = self.filter_unchecked_calls(warnings);
        warnings = self.filter_mev_warnings(warnings, contract_address);
        
        warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_contract_detection() {
        let filter = SmartFilter::new();
        
        // Test WETH9 address
        let weth_addr = H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        assert!(filter.is_safe_contract(Some(weth_addr)));
        
        // Test random address
        let random_addr = H160::from_str("0x1234567890123456789012345678901234567890").unwrap();
        assert!(!filter.is_safe_contract(Some(random_addr)));
    }
    
    #[test]
    fn test_modern_solidity_detection() {
        let filter = SmartFilter::new();
        
        // Bytecode with modern panic pattern
        let modern_bytecode = vec![0x60, 0x00, 0x4e, 0x48, 0x7b, 0x71, 0x60, 0x00];
        assert!(filter.has_modern_protections(&modern_bytecode));
        
        // Legacy bytecode without protections
        let legacy_bytecode = vec![0x60, 0x01, 0x60, 0x02, 0x01, 0x60, 0x00];
        assert!(!filter.has_modern_protections(&legacy_bytecode));
    }
    
    #[test]
    fn test_arithmetic_warning_filtering() {
        let filter = SmartFilter::new();
        
        let overflow_warning = SecurityWarning {
            kind: SecurityWarningKind::IntegerOverflow,
            description: "Integer overflow detected".to_string(),
            severity: SecuritySeverity::High,
            pc: 0,
            operations: Vec::new(),
            remediation: "Use SafeMath".to_string(),
        };
        
        let warnings = vec![overflow_warning];
        
        // Should filter out for WETH9
        let weth_addr = H160::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        let filtered = filter.filter_arithmetic_warnings(warnings.clone(), &[], Some(weth_addr));
        assert_eq!(filtered.len(), 0);
        
        // Should keep for unknown contract
        let random_addr = H160::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let filtered = filter.filter_arithmetic_warnings(warnings, &[], Some(random_addr));
        assert_eq!(filtered.len(), 1);
    }
}
