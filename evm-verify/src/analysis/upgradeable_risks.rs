use crate::bytecode::analyzer::BytecodeAnalyzer;
use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};

/// Upgradeable contract vulnerability types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpgradeableRisk {
    StorageCollision,
    SelectorCollision, 
    UninitializedImplementation,
    InitializationBypass,
    UpgradeAuthBypass,
    SelfDestructRisk,
    MissingStorageGap,
    UntrustedDelegatecall,
    AdminKeyRisk,
    TimelockBypass,
    BeaconProxyRisk,
    DiamondPatternRisk,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProxyPattern {
    Transparent,
    UUPS,
    Beacon,
    Diamond,
    Minimal,
    Custom,
    NotProxy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct u256(pub [u8; 32]);

/// Objective vulnerability details without subjective scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeableVulnerability {
    pub risk_type: UpgradeableRisk,
    pub proxy_pattern: ProxyPattern,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub technical_details: String,
    pub impact_mechanics: String,
    pub detection_confidence: f32, // 0.0-1.0 objective confidence
    pub affected_storage_slots: Vec<u256>,
    pub function_selectors: Vec<[u8; 4]>,
}

#[derive(Debug)]
struct AuthorizationAnalysis {
    is_bypassable: bool,
    has_weak_protection: bool,
    protection_mechanisms: Vec<String>,
}

#[derive(Debug)]
struct AdminAnalysis {
    has_single_admin: bool,
    has_key_rotation: bool,
    admin_count: usize,
    multisig_threshold: Option<usize>,
}

pub struct UpgradeableRiskAnalyzer {
    bytecode: Vec<u8>,
    proxy_signatures: HashMap<[u8; 4], ProxyPattern>,
    admin_functions: HashSet<[u8; 4]>,
    initialization_functions: HashSet<[u8; 4]>,
    upgrade_functions: HashSet<[u8; 4]>,
}

impl UpgradeableRiskAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        let mut proxy_signatures = HashMap::new();
        proxy_signatures.insert([0x36, 0x57, 0x84, 0x30], ProxyPattern::Transparent); // upgradeTo()
        proxy_signatures.insert([0x4f, 0x1e, 0xf2, 0x86], ProxyPattern::Transparent); // upgradeToAndCall()
        proxy_signatures.insert([0x52, 0xd1, 0x90, 0x2d], ProxyPattern::UUPS); // proxiableUUID()
        proxy_signatures.insert([0x59, 0x65, 0x91, 0x65], ProxyPattern::Beacon); // beacon()
        proxy_signatures.insert([0xcd, 0xff, 0xac, 0xd3], ProxyPattern::Diamond); // diamondCut()

        let mut admin_functions = HashSet::new();
        admin_functions.insert([0x8d, 0xa5, 0xcb, 0x5b]); // changeAdmin()
        admin_functions.insert([0x3f, 0x4b, 0xa8, 0x3a]); // transferOwnership()

        let mut initialization_functions = HashSet::new();
        initialization_functions.insert([0x83, 0x4d, 0xfd, 0x47]); // initialize()
        initialization_functions.insert([0xc4, 0xd6, 0x6d, 0xe8]); // initialize(address)

        let mut upgrade_functions = HashSet::new();
        upgrade_functions.insert([0x36, 0x57, 0x84, 0x30]); // upgradeTo()
        upgrade_functions.insert([0x4f, 0x1e, 0xf2, 0x86]); // upgradeToAndCall()

        Self {
            bytecode,
            proxy_signatures,
            admin_functions,
            initialization_functions,
            upgrade_functions,
        }
    }

    /// Detect all upgradeable contract vulnerabilities objectively
    pub fn detect_vulnerabilities(&self) -> Vec<UpgradeableVulnerability> {
        let mut vulnerabilities = Vec::new();
        let proxy_pattern = self.identify_proxy_pattern();

        vulnerabilities.extend(self.detect_storage_collisions(&proxy_pattern));
        vulnerabilities.extend(self.detect_selector_collisions(&proxy_pattern));
        vulnerabilities.extend(self.detect_initialization_issues(&proxy_pattern));
        vulnerabilities.extend(self.detect_upgrade_authorization(&proxy_pattern));
        vulnerabilities.extend(self.detect_implementation_risks(&proxy_pattern));
        vulnerabilities.extend(self.detect_admin_key_risks(&proxy_pattern));
        vulnerabilities.extend(self.detect_delegatecall_risks(&proxy_pattern));

        vulnerabilities
    }

    fn identify_proxy_pattern(&self) -> ProxyPattern {
        let mut pattern_scores = HashMap::new();
        
        if self.is_minimal_proxy() {
            return ProxyPattern::Minimal;
        }
        
        for i in 0..self.bytecode.len().saturating_sub(4) {
            let sig = [self.bytecode[i], self.bytecode[i+1], self.bytecode[i+2], self.bytecode[i+3]];
            if let Some(pattern) = self.proxy_signatures.get(&sig) {
                *pattern_scores.entry(pattern.clone()).or_insert(0) += 1;
            }
        }

        pattern_scores.into_iter()
            .max_by_key(|(_, score)| *score)
            .map(|(pattern, _)| pattern)
            .unwrap_or(ProxyPattern::NotProxy)
    }

    fn is_minimal_proxy(&self) -> bool {
        let minimal_pattern = [0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d, 0x73];
        for i in 0..self.bytecode.len().saturating_sub(minimal_pattern.len()) {
            if self.bytecode[i..i + minimal_pattern.len()] == minimal_pattern {
                return true;
            }
        }
        false
    }

    fn detect_storage_collisions(&self, proxy_pattern: &ProxyPattern) -> Vec<UpgradeableVulnerability> {
        let mut vulnerabilities = Vec::new();
        let storage_usage = self.analyze_storage_usage();
        
        for (slot, usage_count) in storage_usage {
            if usage_count > 1 && !self.is_standard_proxy_slot(&slot) {
                vulnerabilities.push(UpgradeableVulnerability {
                    risk_type: UpgradeableRisk::StorageCollision,
                    proxy_pattern: proxy_pattern.clone(),
                    severity: SecuritySeverity::Critical,
                    location: 0,
                    description: format!("Storage slot collision detected in slot {:?}", slot),
                    technical_details: format!("Storage slot accessed {} times across different contexts", usage_count),
                    impact_mechanics: "Multiple writes to same storage slot can corrupt state during upgrades".to_string(),
                    detection_confidence: 0.95,
                    affected_storage_slots: vec![slot],
                    function_selectors: vec![],
                });
            }
        }

        vulnerabilities
    }

    fn detect_selector_collisions(&self, proxy_pattern: &ProxyPattern) -> Vec<UpgradeableVulnerability> {
        let mut vulnerabilities = Vec::new();
        let selectors = self.extract_function_selectors();
        let mut selector_counts = HashMap::new();

        for selector in selectors {
            *selector_counts.entry(selector).or_insert(0) += 1;
        }

        for (selector, count) in selector_counts {
            if count > 1 && !self.is_expected_selector_override(&selector) {
                vulnerabilities.push(UpgradeableVulnerability {
                    risk_type: UpgradeableRisk::SelectorCollision,
                    proxy_pattern: proxy_pattern.clone(),
                    severity: SecuritySeverity::High,
                    location: 0,
                    description: format!("Function selector collision: 0x{:02x}{:02x}{:02x}{:02x}", 
                        selector[0], selector[1], selector[2], selector[3]),
                    technical_details: format!("Selector appears {} times in bytecode", count),
                    impact_mechanics: "Function calls may be routed to wrong implementation".to_string(),
                    detection_confidence: 0.90,
                    affected_storage_slots: vec![],
                    function_selectors: vec![selector],
                });
            }
        }

        vulnerabilities
    }

    fn detect_initialization_issues(&self, proxy_pattern: &ProxyPattern) -> Vec<UpgradeableVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(4) {
            let sig = [self.bytecode[i], self.bytecode[i+1], self.bytecode[i+2], self.bytecode[i+3]];
            
            if self.initialization_functions.contains(&sig) {
                if !self.has_initialization_protection(i) {
                    vulnerabilities.push(UpgradeableVulnerability {
                        risk_type: UpgradeableRisk::InitializationBypass,
                        proxy_pattern: proxy_pattern.clone(),
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "Initialization function lacks re-initialization protection".to_string(),
                        technical_details: "No SLOAD/ISZERO pattern found for initialization flag".to_string(),
                        impact_mechanics: "Function can be called multiple times to reset contract state".to_string(),
                        detection_confidence: 0.88,
                        affected_storage_slots: vec![],
                        function_selectors: vec![sig],
                    });
                }

                if self.is_implementation_uninitialized(i) {
                    vulnerabilities.push(UpgradeableVulnerability {
                        risk_type: UpgradeableRisk::UninitializedImplementation,
                        proxy_pattern: proxy_pattern.clone(),
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Implementation contract appears uninitialized".to_string(),
                        technical_details: "No constructor initialization pattern detected".to_string(),
                        impact_mechanics: "Uninitialized implementation can be claimed by attackers".to_string(),
                        detection_confidence: 0.75,
                        affected_storage_slots: vec![],
                        function_selectors: vec![sig],
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_upgrade_authorization(&self, proxy_pattern: &ProxyPattern) -> Vec<UpgradeableVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(4) {
            let sig = [self.bytecode[i], self.bytecode[i+1], self.bytecode[i+2], self.bytecode[i+3]];
            
            if self.upgrade_functions.contains(&sig) {
                let auth_analysis = self.analyze_upgrade_authorization(i);
                
                if auth_analysis.is_bypassable {
                    vulnerabilities.push(UpgradeableVulnerability {
                        risk_type: UpgradeableRisk::UpgradeAuthBypass,
                        proxy_pattern: proxy_pattern.clone(),
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "Upgrade authorization can be bypassed".to_string(),
                        technical_details: format!("Protection mechanisms: {:?}", auth_analysis.protection_mechanisms),
                        impact_mechanics: "Unauthorized parties can upgrade contract to malicious implementation".to_string(),
                        detection_confidence: 0.92,
                        affected_storage_slots: vec![],
                        function_selectors: vec![sig],
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_implementation_risks(&self, proxy_pattern: &ProxyPattern) -> Vec<UpgradeableVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xff { // SELFDESTRUCT
                vulnerabilities.push(UpgradeableVulnerability {
                    risk_type: UpgradeableRisk::SelfDestructRisk,
                    proxy_pattern: proxy_pattern.clone(),
                    severity: SecuritySeverity::Critical,
                    location: i,
                    description: "SELFDESTRUCT instruction found in implementation".to_string(),
                    technical_details: format!("SELFDESTRUCT opcode at position {}", i),
                    impact_mechanics: "Contract can be permanently destroyed, breaking proxy".to_string(),
                    detection_confidence: 1.0,
                    affected_storage_slots: vec![],
                    function_selectors: vec![],
                });
            }
        }

        vulnerabilities
    }

    fn detect_admin_key_risks(&self, proxy_pattern: &ProxyPattern) -> Vec<UpgradeableVulnerability> {
        let mut vulnerabilities = Vec::new();
        let admin_analysis = self.analyze_admin_security();

        if admin_analysis.has_single_admin && admin_analysis.multisig_threshold.is_none() {
            vulnerabilities.push(UpgradeableVulnerability {
                risk_type: UpgradeableRisk::AdminKeyRisk,
                proxy_pattern: proxy_pattern.clone(),
                severity: SecuritySeverity::High,
                location: 0,
                description: "Single admin key controls critical functions".to_string(),
                technical_details: format!("Admin count: {}, Multisig: {:?}", 
                    admin_analysis.admin_count, admin_analysis.multisig_threshold),
                impact_mechanics: "Single key compromise grants full contract control".to_string(),
                detection_confidence: 0.85,
                affected_storage_slots: vec![],
                function_selectors: vec![],
            });
        }

        vulnerabilities
    }

    fn detect_delegatecall_risks(&self, proxy_pattern: &ProxyPattern) -> Vec<UpgradeableVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xf4 { // DELEGATECALL
                if !self.has_delegatecall_validation(i) {
                    vulnerabilities.push(UpgradeableVulnerability {
                        risk_type: UpgradeableRisk::UntrustedDelegatecall,
                        proxy_pattern: proxy_pattern.clone(),
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "DELEGATECALL to unvalidated address".to_string(),
                        technical_details: format!("DELEGATECALL at position {} without address validation", i),
                        impact_mechanics: "Arbitrary code execution in proxy context".to_string(),
                        detection_confidence: 0.90,
                        affected_storage_slots: vec![],
                        function_selectors: vec![],
                    });
                }
            }
        }

        vulnerabilities
    }

    // Helper method implementations
    fn analyze_storage_usage(&self) -> HashMap<u256, usize> {
        let mut storage_usage = HashMap::new();
        
        for i in 0..self.bytecode.len().saturating_sub(32) {
            if self.bytecode[i] == 0x55 { // SSTORE
                if let Some(slot) = self.extract_storage_slot(i) {
                    *storage_usage.entry(slot).or_insert(0) += 1;
                }
            }
        }
        
        storage_usage
    }

    fn extract_storage_slot(&self, sstore_pos: usize) -> Option<u256> {
        let start = sstore_pos.saturating_sub(40);
        
        for i in (start..sstore_pos).rev() {
            if i < self.bytecode.len() {
                match self.bytecode[i] {
                    0x7f => { // PUSH32
                        if i + 32 < self.bytecode.len() {
                            let mut slot_bytes = [0u8; 32];
                            slot_bytes.copy_from_slice(&self.bytecode[i+1..i+33]);
                            return Some(u256(slot_bytes));
                        }
                    }
                    0x60..=0x7e => { // Other PUSH operations
                        let push_size = (self.bytecode[i] - 0x5f) as usize;
                        if i + push_size < self.bytecode.len() {
                            let mut slot_bytes = [0u8; 32];
                            let data = &self.bytecode[i+1..i+1+push_size];
                            slot_bytes[32-push_size..].copy_from_slice(data);
                            return Some(u256(slot_bytes));
                        }
                    }
                    _ => continue,
                }
            }
        }
        None
    }

    fn is_standard_proxy_slot(&self, _slot: &u256) -> bool {
        false // Would need keccak256 for precise checking
    }

    fn extract_function_selectors(&self) -> Vec<[u8; 4]> {
        let mut selectors = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(4) {
            if self.bytecode[i] == 0x63 { // PUSH4
                if i + 6 < self.bytecode.len() && self.bytecode[i + 5] == 0x14 { // EQ
                    let selector = [
                        self.bytecode[i + 1],
                        self.bytecode[i + 2], 
                        self.bytecode[i + 3],
                        self.bytecode[i + 4],
                    ];
                    selectors.push(selector);
                }
            }
        }
        
        selectors
    }

    fn is_expected_selector_override(&self, _selector: &[u8; 4]) -> bool {
        false // Would check against known safe overrides
    }

    fn has_initialization_protection(&self, pos: usize) -> bool {
        let start = pos.saturating_sub(100);
        let end = (pos + 100).min(self.bytecode.len());
        
        for i in start..end {
            if i + 4 < self.bytecode.len() {
                if self.bytecode[i] == 0x54 && // SLOAD
                   i + 10 < self.bytecode.len() && self.bytecode[i + 10] == 0x15 { // ISZERO
                    return true;
                }
            }
        }
        false
    }

    fn is_implementation_uninitialized(&self, _pos: usize) -> bool {
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x60 && self.bytecode[i + 1] == 0x01 && // PUSH1 1
               i + 5 < self.bytecode.len() && self.bytecode[i + 5] == 0x55 { // SSTORE
                return false;
            }
        }
        true
    }

    fn analyze_upgrade_authorization(&self, pos: usize) -> AuthorizationAnalysis {
        let start = pos.saturating_sub(200);
        let end = (pos + 50).min(self.bytecode.len());
        
        let mut has_caller_check = false;
        let mut has_role_check = false;
        let mut protection_mechanisms = Vec::new();
        
        for i in start..end {
            if i + 4 < self.bytecode.len() {
                let sig = [self.bytecode[i], self.bytecode[i+1], self.bytecode[i+2], self.bytecode[i+3]];
                
                if sig == [0x33, 0x14, 0x60, 0x40] || self.admin_functions.contains(&sig) {
                    has_caller_check = true;
                    protection_mechanisms.push("caller_check".to_string());
                }
                
                if sig == [0x91, 0xd1, 0x48, 0x54] { // hasRole()
                    has_role_check = true;
                    protection_mechanisms.push("role_based".to_string());
                }
            }
        }
        
        AuthorizationAnalysis {
            is_bypassable: !has_caller_check && !has_role_check,
            has_weak_protection: has_caller_check && !has_role_check,
            protection_mechanisms,
        }
    }

    fn analyze_admin_security(&self) -> AdminAnalysis {
        let mut admin_count = 0;
        let mut has_rotation = false;
        
        for i in 0..self.bytecode.len().saturating_sub(4) {
            let sig = [self.bytecode[i], self.bytecode[i+1], self.bytecode[i+2], self.bytecode[i+3]];
            
            if self.admin_functions.contains(&sig) {
                admin_count += 1;
                
                if sig == [0x3f, 0x4b, 0xa8, 0x3a] { // transferOwnership()
                    has_rotation = true;
                }
            }
        }
        
        AdminAnalysis {
            has_single_admin: admin_count <= 1,
            has_key_rotation: has_rotation,
            admin_count,
            multisig_threshold: None, // Would need deeper analysis
        }
    }

    fn has_delegatecall_validation(&self, pos: usize) -> bool {
        let start = pos.saturating_sub(50);
        
        for i in start..pos {
            if i < self.bytecode.len() && self.bytecode[i] == 0x14 { // EQ (address comparison)
                return true;
            }
        }
        false
    }
}
