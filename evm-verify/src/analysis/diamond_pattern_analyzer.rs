use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DiamondVulnerabilityType {
    FacetCollision,
    SelectorClash,
    StorageLayoutConflict,
    UpgradeOrderingIssue,
    FacetCutReentrancy,
    DelegateCallUnchecked,
    FacetAddressZero,
    ImmutableFacetOverwrite,
    LooupeFunctionMissing,
    DiamondStorageCollision,
    FacetInitializationFailure,
    SelectorFreeze,
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
pub struct DiamondVulnerability {
    pub vulnerability_type: DiamondVulnerabilityType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct DiamondPatternAnalyzer {
    bytecode: Vec<u8>,
}

impl DiamondPatternAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DiamondVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_facet_collisions());
        vulnerabilities.extend(self.detect_selector_clashes());
        vulnerabilities.extend(self.detect_storage_layout_conflicts());
        vulnerabilities.extend(self.detect_facet_cut_issues());
        vulnerabilities.extend(self.detect_delegate_call_issues());
        vulnerabilities.extend(self.detect_loupe_compliance());

        vulnerabilities
    }

    fn detect_diamond_pattern(&self) -> bool {
        // Look for DiamondCut function signature
        let diamond_sigs = [
            &[0x1f, 0x93, 0x1c, 0x1c][..], // diamondCut(FacetCut[],address,bytes)
            &[0xcd, 0xff, 0xac, 0xd8][..], // facets()
            &[0xad, 0xf4, 0x09, 0x5a][..], // facetAddress(bytes4)
        ];

        diamond_sigs.iter().filter(|&&sig| {
            self.bytecode.windows(sig.len()).any(|w| w == sig)
        }).count() >= 1
    }

    fn detect_facet_collisions(&self) -> Vec<DiamondVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.detect_diamond_pattern() {
            return vulnerabilities;
        }

        // Look for diamondCut function
        let diamond_cut_sig = &[0x1f, 0x93, 0x1c, 0x1c][..]; // diamondCut()
        
        if let Some(pos) = self.bytecode.windows(diamond_cut_sig.len()).position(|w| w == diamond_cut_sig) {
            let function_section = &self.bytecode[pos..pos.saturating_add(200).min(self.bytecode.len())];
            
            // Check for selector uniqueness validation
            let has_uniqueness_check = function_section.windows(6).any(|w| {
                // Look for pattern: SLOAD selector mapping, check if exists
                w.contains(&0x54) && // SLOAD (check if selector already registered)
                w.contains(&0x15) && // ISZERO
                w.contains(&0x57)    // JUMPI (revert if collision)
            });

            if !has_uniqueness_check {
                vulnerabilities.push(DiamondVulnerability {
                    vulnerability_type: DiamondVulnerabilityType::FacetCollision,
                    severity: SecuritySeverity::Critical,
                    location: pos,
                    description: "diamondCut doesn't validate selector uniqueness across facets".to_string(),
                    exploit_scenario: "Same function selector can be registered to multiple facets, causing unpredictable behavior or allowing override of critical functions".to_string(),
                    remediation: "Validate that each selector is unique and not already registered before adding to diamond".to_string(),
                });
            }

            // Check for facet address validation
            let validates_address = function_section.windows(4).any(|w| {
                w[0] == 0x15 && // ISZERO (check if address is zero)
                w[1] == 0x15 && // ISZERO (negate)
                w[2] == 0x57    // JUMPI (revert if zero)
            });

            if !validates_address {
                vulnerabilities.push(DiamondVulnerability {
                    vulnerability_type: DiamondVulnerabilityType::FacetAddressZero,
                    severity: SecuritySeverity::High,
                    location: pos,
                    description: "diamondCut doesn't validate facet addresses are non-zero".to_string(),
                    exploit_scenario: "Zero address facets cause all calls to fail, permanently bricking diamond functionality".to_string(),
                    remediation: "Add require(facetAddress != address(0)) for Add and Replace actions".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn detect_selector_clashes(&self) -> Vec<DiamondVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Extract all function selectors from bytecode (first 4 bytes of keccak256(signature))
        let mut selectors = HashSet::new();
        let mut duplicates = Vec::new();

        // Scan bytecode for function selector patterns (PUSH4 followed by EQ)
        for i in 0..self.bytecode.len().saturating_sub(6) {
            if self.bytecode[i] == 0x63 { // PUSH4
                if i + 5 < self.bytecode.len() {
                    let selector = &self.bytecode[i+1..i+5];
                    let selector_u32 = u32::from_be_bytes([
                        selector[0],
                        selector[1],
                        selector[2],
                        selector[3],
                    ]);
                    
                    if !selectors.insert(selector_u32) {
                        duplicates.push((i, selector_u32));
                    }
                }
            }
        }

        if !duplicates.is_empty() {
            vulnerabilities.push(DiamondVulnerability {
                vulnerability_type: DiamondVulnerabilityType::SelectorClash,
                severity: SecuritySeverity::Critical,
                location: duplicates[0].0,
                description: format!("Function selector collision detected - {} duplicate selectors found", duplicates.len()),
                exploit_scenario: "Multiple functions with same selector cause unpredictable routing in diamond proxy".to_string(),
                remediation: "Ensure all function selectors are unique across all facets. Use DiamondLoupe to verify".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_storage_layout_conflicts(&self) -> Vec<DiamondVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.detect_diamond_pattern() {
            return vulnerabilities;
        }

        // Check for diamond storage pattern (EIP-2535 recommends specific storage slot)
        // Diamond storage uses: keccak256("diamond.standard.diamond.storage")
        let _diamond_storage_pattern = self.bytecode.windows(32).any(|w| {
            // Look for specific storage slot calculation
            w.contains(&0x20) && // SHA3
            w.contains(&0x54)    // SLOAD
        });

        // Check for storage collision prevention
        let uses_namespaced_storage = self.bytecode.windows(10).any(|w| {
            // Look for structured storage access patterns
            w.contains(&0x20) && // SHA3 (for namespace)
            w.contains(&0x01) && // ADD (offset calculation)
            w.contains(&0x54)    // SLOAD
        });

        if !uses_namespaced_storage {
            vulnerabilities.push(DiamondVulnerability {
                vulnerability_type: DiamondVulnerabilityType::DiamondStorageCollision,
                severity: SecuritySeverity::High,
                location: 0,
                description: "Diamond doesn't use namespaced storage pattern".to_string(),
                exploit_scenario: "Facets may overwrite each other's storage, causing data corruption and unpredictable behavior".to_string(),
                remediation: "Use diamond storage pattern: struct DiamondStorage at keccak256('diamond.standard.diamond.storage')".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_facet_cut_issues(&self) -> Vec<DiamondVulnerability> {
        let mut vulnerabilities = Vec::new();

        let diamond_cut_sig = &[0x1f, 0x93, 0x1c, 0x1c][..]; // diamondCut()
        
        if let Some(pos) = self.bytecode.windows(diamond_cut_sig.len()).position(|w| w == diamond_cut_sig) {
            let function_section = &self.bytecode[pos..pos.saturating_add(250).min(self.bytecode.len())];
            
            // Check for reentrancy guard
            let has_reentrancy_guard = function_section.windows(4).any(|w| {
                w[0] == 0x54 && // SLOAD (locked flag)
                w[1] == 0x15 && // ISZERO
                w[2] == 0x57    // JUMPI (revert if locked)
            });

            if !has_reentrancy_guard {
                vulnerabilities.push(DiamondVulnerability {
                    vulnerability_type: DiamondVulnerabilityType::FacetCutReentrancy,
                    severity: SecuritySeverity::Critical,
                    location: pos,
                    description: "diamondCut lacks reentrancy protection".to_string(),
                    exploit_scenario: "Malicious facet init function can reenter diamondCut to manipulate facet registry during upgrade".to_string(),
                    remediation: "Add nonReentrant modifier to diamondCut function".to_string(),
                });
            }

            // Check for facet initialization call
            let has_init_call = function_section.contains(&0xf2); // DELEGATECALL

            if has_init_call {
                // Verify init call success is checked
                let checks_call_result = function_section.windows(3).any(|w| {
                    w[0] == 0x15 && // ISZERO (check if call failed)
                    w[1] == 0x57    // JUMPI (revert if failed)
                });

                if !checks_call_result {
                    vulnerabilities.push(DiamondVulnerability {
                        vulnerability_type: DiamondVulnerabilityType::FacetInitializationFailure,
                        severity: SecuritySeverity::High,
                        location: pos,
                        description: "Facet initialization call result not validated".to_string(),
                        exploit_scenario: "Failed facet initialization goes unnoticed, leaving diamond in inconsistent state".to_string(),
                        remediation: "Check DELEGATECALL result: require(success, 'Init failed')".to_string(),
                    });
                }
            }

            // Check for immutable function protection
            let has_freeze_mechanism = self.bytecode.windows(5).any(|w| {
                w.contains(&0x54) && // SLOAD (check frozen flag)
                w.contains(&0x15) && // ISZERO
                w.contains(&0x57)    // JUMPI
            });

            if !has_freeze_mechanism {
                vulnerabilities.push(DiamondVulnerability {
                    vulnerability_type: DiamondVulnerabilityType::SelectorFreeze,
                    severity: SecuritySeverity::Medium,
                    location: pos,
                    description: "No mechanism to freeze critical selectors from modification".to_string(),
                    exploit_scenario: "Critical functions like diamondCut itself can be removed or replaced maliciously".to_string(),
                    remediation: "Implement selector freeze list to protect critical diamond functions".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn detect_delegate_call_issues(&self) -> Vec<DiamondVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Diamond fallback delegates calls to facets
        // Look for DELEGATECALL in fallback
        if let Some(pos) = self.bytecode.iter().position(|&b| b == 0xf2) { // DELEGATECALL
            let context = if pos >= 20 {
                &self.bytecode[pos-20..(pos+30).min(self.bytecode.len())]
            } else {
                &self.bytecode[pos..(pos+30).min(self.bytecode.len())]
            };
            
            // Check if facet address is validated before delegatecall
            let validates_facet = context.windows(4).any(|w| {
                w[0] == 0x15 && // ISZERO (check if address is zero)
                w[1] == 0x15 && // ISZERO (negate)
                w[2] == 0x57    // JUMPI (revert if zero)
            });

            if !validates_facet {
                vulnerabilities.push(DiamondVulnerability {
                    vulnerability_type: DiamondVulnerabilityType::DelegateCallUnchecked,
                    severity: SecuritySeverity::Critical,
                    location: pos,
                    description: "DELEGATECALL to facet without address validation".to_string(),
                    exploit_scenario: "Calling unregistered selector delegates to address(0), causing revert or undefined behavior".to_string(),
                    remediation: "Validate facet address exists and is non-zero before DELEGATECALL".to_string(),
                });
            }

            // Check if delegatecall result is handled
            let handles_result = context.windows(10).any(|w| {
                w.contains(&0x3d) && // RETURNDATASIZE
                w.contains(&0x3e)    // RETURNDATACOPY
            });

            if !handles_result {
                vulnerabilities.push(DiamondVulnerability {
                    vulnerability_type: DiamondVulnerabilityType::DelegateCallUnchecked,
                    severity: SecuritySeverity::Medium,
                    location: pos,
                    description: "DELEGATECALL return data not properly handled".to_string(),
                    exploit_scenario: "Failed facet calls don't propagate errors correctly, hiding failures".to_string(),
                    remediation: "Properly bubble up revert reasons using returndatacopy and revert".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn detect_loupe_compliance(&self) -> Vec<DiamondVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.detect_diamond_pattern() {
            return vulnerabilities;
        }

        // DiamondLoupe interface requires these functions
        let loupe_functions = [
            &[0xcd, 0xff, 0xac, 0xd8][..], // facets()
            &[0xad, 0xf4, 0x09, 0x5a][..], // facetFunctionSelectors(address)
            &[0x52, 0xef, 0x6b, 0x2c][..], // facetAddresses()
            &[0x01, 0xfd, 0xc6, 0xc0][..], // facetAddress(bytes4)
        ];

        let mut missing_functions = Vec::new();
        for (i, sig) in loupe_functions.iter().enumerate() {
            if !self.bytecode.windows(sig.len()).any(|w| w == *sig) {
                missing_functions.push(i);
            }
        }

        if !missing_functions.is_empty() {
            let function_names = ["facets()", "facetFunctionSelectors()", "facetAddresses()", "facetAddress()"];
            let missing_names: Vec<_> = missing_functions.iter()
                .map(|&i| function_names[i])
                .collect();
            
            vulnerabilities.push(DiamondVulnerability {
                vulnerability_type: DiamondVulnerabilityType::LooupeFunctionMissing,
                severity: SecuritySeverity::Medium,
                location: 0,
                description: format!("Missing DiamondLoupe functions: {}", missing_names.join(", ")),
                exploit_scenario: "Cannot introspect diamond structure, making it difficult to verify configuration and debug issues".to_string(),
                remediation: "Implement full DiamondLoupe interface (EIP-2535) for transparency and tooling compatibility".to_string(),
            });
        }

        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_diamond_pattern() {
        let bytecode = vec![
            0x1f, 0x93, 0x1c, 0x1c, // diamondCut()
        ];
        
        let analyzer = DiamondPatternAnalyzer::new(bytecode);
        assert!(analyzer.detect_diamond_pattern());
    }

    #[test]
    fn test_facet_collision_detection() {
        let bytecode = vec![
            0x1f, 0x93, 0x1c, 0x1c, // diamondCut()
            0x55, // SSTORE without uniqueness check
        ];
        
        let analyzer = DiamondPatternAnalyzer::new(bytecode);
        let vulns = analyzer.detect_facet_collisions();
        assert!(!vulns.is_empty());
    }

    #[test]
    fn test_selector_clash() {
        let bytecode = vec![
            0x63, 0x12, 0x34, 0x56, 0x78, // PUSH4 selector1
            0x14, // EQ
            0x63, 0x12, 0x34, 0x56, 0x78, // PUSH4 selector1 (duplicate)
            0x14, // EQ
        ];
        
        let analyzer = DiamondPatternAnalyzer::new(bytecode);
        let vulns = analyzer.detect_selector_clashes();
        assert!(!vulns.is_empty());
    }
}
