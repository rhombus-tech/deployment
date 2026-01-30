/// ERC-6900 Modular Account Plugin Vulnerability Detector
///
/// Detects vulnerabilities in ERC-6900 modular smart account plugins.
/// This is THE standard for modular AA (Alchemy, Biconomy, Safe Protocol).
///
/// Real-world context:
/// - $10B+ in modular smart accounts (Alchemy, Biconomy, Safe)
/// - Plugin ecosystem enables composable account features
/// - Attack surface: Plugin installation, execution, storage conflicts
/// - Risk: One malicious plugin can drain all account funds

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc6900PluginVulnerability {
    pub vulnerability_type: Erc6900PluginVulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc6900PluginVulnerabilityType {
    PluginSelectorCollision,        // Multiple plugins handle same selector
    UnprotectedPluginInstall,       // Anyone can install malicious plugin
    PluginStorageConflict,          // Plugins overwrite each other's storage
    MissingPluginValidation,        // No validation before plugin execution
    PluginDependencyLoop,           // Circular plugin dependencies
    PluginUpgradeRaceCondition,     // Race during plugin upgrade
    HookInterferenceCascade,        // Pre/post hooks interfere with each other
    PluginPermissionEscalation,     // Plugin gains unauthorized permissions
    PluginUninstallBypass,          // Cannot remove malicious plugin
    ManifestHashMismatch,           // Plugin manifest doesn't match code
}

pub struct Erc6900PluginDetector {
    bytecode: Vec<u8>,
}

impl Erc6900PluginDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Erc6900PluginVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // 1. Plugin selector collision
        if let Some(vuln) = self.detect_selector_collision() {
            vulnerabilities.push(vuln);
        }
        
        // 2. Unprotected plugin installation
        if let Some(vuln) = self.detect_unprotected_install() {
            vulnerabilities.push(vuln);
        }
        
        // 3. Storage conflict between plugins
        if let Some(vuln) = self.detect_storage_conflict() {
            vulnerabilities.push(vuln);
        }
        
        // 4. Missing plugin validation
        if let Some(vuln) = self.detect_missing_validation() {
            vulnerabilities.push(vuln);
        }
        
        // 5. Hook interference
        if let Some(vuln) = self.detect_hook_interference() {
            vulnerabilities.push(vuln);
        }
        
        vulnerabilities
    }
    
    fn detect_selector_collision(&self) -> Option<Erc6900PluginVulnerability> {
        // ERC-6900 uses function selectors to route calls to plugins
        // If two plugins register same selector, last one wins → security bypass
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for plugin registration without collision check
            // Pattern: Store selector → plugin mapping without duplicate check
            
            let mut has_selector_storage = false;
            let mut has_collision_check = false;
            
            for j in i..self.bytecode.len().min(i + 30) {
                if self.bytecode[j] == 0x55 { // SSTORE (storing selector mapping)
                    has_selector_storage = true;
                }
                
                // Collision check would be: SLOAD → ISZERO → REVERT
                if self.bytecode[j] == 0x54 { // SLOAD (checking existing)
                    if j + 3 < self.bytecode.len() &&
                       self.bytecode[j+1] == 0x15 && // ISZERO
                       self.bytecode[j+2] == 0xFD { // REVERT
                        has_collision_check = true;
                    }
                }
            }
            
            if has_selector_storage && !has_collision_check {
                return Some(Erc6900PluginVulnerability {
                    vulnerability_type: Erc6900PluginVulnerabilityType::PluginSelectorCollision,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Plugin installation doesn't check for selector collisions. \
                                Multiple plugins can register same function selector, causing \
                                unpredictable behavior and security bypasses.".to_string(),
                    exploit_scenario: "1. Victim installs SessionKey plugin (manages session keys)\n\
                                      2. Attacker installs malicious plugin with same execute() selector\n\
                                      3. Malicious plugin overrides SessionKey plugin\n\
                                      4. All session key validations now bypass attacker's code\n\
                                      5. Attacker drains entire account\n\
                                      6. Similar to Safe Protocol plugin collision issues".to_string(),
                    recommendation: "Before installing plugin, check if any selector already registered: \
                                  require(selectorToPlugin[selector] == address(0)). Implement plugin \
                                  registry with uniqueness constraints. Consider versioned plugin system. \
                                  Add plugin removal/replacement flows.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_unprotected_install(&self) -> Option<Erc6900PluginVulnerability> {
        // Plugin installation must be protected (owner-only or governance)
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for plugin install function
            if i + 4 < self.bytecode.len() {
                let selector = &self.bytecode[i..i+4];
                // installPlugin() selector
                if selector == [0xa1, 0x5c, 0x3d, 0x4f] {
                    // Check for access control before installation
                    let mut has_access_control = false;
                    
                    for j in i..self.bytecode.len().min(i + 20) {
                        // Owner check or permission check
                        if self.bytecode[j] == 0x33 { // CALLER
                            if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x14 { // EQ
                                has_access_control = true;
                            }
                        }
                    }
                    
                    if !has_access_control {
                        return Some(Erc6900PluginVulnerability {
                            vulnerability_type: Erc6900PluginVulnerabilityType::UnprotectedPluginInstall,
                            severity: "Critical".to_string(),
                            location: vec![i],
                            description: "Plugin installation function lacks access control. Anyone can \
                                        install arbitrary plugins into account, gaining full control.".to_string(),
                            exploit_scenario: "1. Attacker finds victim's smart account address\n\
                                              2. Calls installPlugin() with malicious plugin\n\
                                              3. No owner check, installation succeeds\n\
                                              4. Malicious plugin has preExecutionHook()\n\
                                              5. Hook diverts all funds to attacker before execution\n\
                                              6. Victim account completely compromised\n\
                                              7. $10M+ potential impact across AA ecosystem".to_string(),
                            recommendation: "Add onlyOwner or onlySelf modifier to installPlugin(). \
                                          Require signature from account owner. Consider timelock for \
                                          plugin installation. Implement plugin whitelist/registry. \
                                          Example: require(msg.sender == owner || msg.sender == address(this))".to_string(),
                        });
                    }
                }
            }
        }
        
        None
    }
    
    fn detect_storage_conflict(&self) -> Option<Erc6900PluginVulnerability> {
        // Plugins share account's storage - must use namespaced storage
        
        for i in 0..self.bytecode.len().saturating_sub(15) {
            // Look for DELEGATECALL to plugin (plugin runs in account context)
            if self.bytecode[i] == 0xF4 { // DELEGATECALL
                // Check if storage access uses namespacing
                let mut has_namespace = false;
                
                // Namespacing typically uses hash(pluginAddress + slot)
                for j in i.saturating_sub(10)..i {
                    if self.bytecode[j] == 0x20 { // KECCAK256 (hashing for namespace)
                        has_namespace = true;
                    }
                }
                
                if !has_namespace {
                    return Some(Erc6900PluginVulnerability {
                        vulnerability_type: Erc6900PluginVulnerabilityType::PluginStorageConflict,
                        severity: "High".to_string(),
                        location: vec![i],
                        description: "Plugins use delegatecall without namespaced storage. Multiple \
                                    plugins can overwrite each other's storage slots, causing data \
                                    corruption and security bypasses.".to_string(),
                        exploit_scenario: "1. SessionKey plugin stores keys at slot 0\n\
                                          2. Recovery plugin stores guardians at slot 0 (conflict!)\n\
                                          3. Installing recovery plugin overwrites session keys\n\
                                          4. All active sessions invalidated\n\
                                          5. Or worse: guardian address overwrites key → unauthorized access\n\
                                          6. Similar to diamond proxy storage collision issues".to_string(),
                        recommendation: "Use ERC-7201 namespaced storage: keccak256(pluginAddress, slot). \
                                      Reserve storage slots per plugin. Use diamond storage pattern. \
                                      Implement storage layout registry. Add storage conflict detection. \
                                      Reference: EIP-2535 storage best practices.".to_string(),
                    });
                }
            }
        }
        
        None
    }
    
    fn detect_missing_validation(&self) -> Option<Erc6900PluginVulnerability> {
        // Before executing plugin, must validate it's properly installed
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for plugin execution
            let mut has_plugin_call = false;
            let mut has_validation = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                if self.bytecode[j] == 0xF4 || self.bytecode[j] == 0xF1 { // DELEGATECALL/CALL
                    has_plugin_call = true;
                }
                
                // Validation: load plugin status, check if installed
                if self.bytecode[j] == 0x54 { // SLOAD (loading plugin status)
                    if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x15 { // ISZERO
                        has_validation = true;
                    }
                }
            }
            
            if has_plugin_call && !has_validation {
                return Some(Erc6900PluginVulnerability {
                    vulnerability_type: Erc6900PluginVulnerabilityType::MissingPluginValidation,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Account executes plugin code without validating plugin is properly \
                                installed and authorized. Attacker can call uninstalled/malicious plugins.".to_string(),
                    exploit_scenario: "1. Victim uninstalls suspicious plugin for security\n\
                                      2. Plugin address still in memory/logs\n\
                                      3. Attacker crafts transaction calling uninstalled plugin\n\
                                      4. Account doesn't validate plugin status\n\
                                      5. Executes malicious plugin via delegatecall\n\
                                      6. Plugin drains account despite being 'uninstalled'".to_string(),
                    recommendation: "Before plugin execution: require(installedPlugins[plugin]). \
                                  Validate plugin manifest hash. Check plugin hasn't been uninstalled. \
                                  Verify plugin permissions. Maintain plugin registry with status. \
                                  Add execution guards around all plugin calls.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_hook_interference(&self) -> Option<Erc6900PluginVulnerability> {
        // Plugins have pre/post execution hooks that can interfere
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for multiple hook executions
            let mut hook_count = 0;
            let mut has_isolation = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                // Hook execution (likely CALL or DELEGATECALL)
                if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xF4 {
                    hook_count += 1;
                }
                
                // Isolation via try-catch or gas limits
                if self.bytecode[j] == 0x3D { // RETURNDATASIZE (error handling)
                    has_isolation = true;
                }
            }
            
            if hook_count >= 2 && !has_isolation {
                return Some(Erc6900PluginVulnerability {
                    vulnerability_type: Erc6900PluginVulnerabilityType::HookInterferenceCascade,
                    severity: "Medium".to_string(),
                    location: vec![i],
                    description: "Multiple plugin hooks execute without isolation. One plugin's hook \
                                can interfere with another's, causing unexpected behavior or DOS.".to_string(),
                    exploit_scenario: "1. User has 2FA plugin (preExecutionHook validates 2FA)\n\
                                      2. User installs rate-limit plugin (limits tx per hour)\n\
                                      3. Rate-limit plugin's hook reverts (limit exceeded)\n\
                                      4. Revert bubbles up, cancels entire transaction\n\
                                      5. 2FA validation never happens\n\
                                      6. User can't access account despite having 2FA\n\
                                      7. Or malicious plugin DOS all other plugins".to_string(),
                    recommendation: "Isolate hook execution with try-catch. Set gas limits per hook. \
                                  Execute hooks in sandboxes. Handle hook failures gracefully. \
                                  Allow hook priority/ordering configuration. Add hook timeout. \
                                  Consider hook circuit breaker pattern.".to_string(),
                });
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_selector_collision() {
        // SSTORE without collision check
        let bytecode = vec![
            0x55, // SSTORE (no prior SLOAD check)
        ];
        
        let detector = Erc6900PluginDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            Erc6900PluginVulnerabilityType::PluginSelectorCollision
        )));
    }
    
    #[test]
    fn test_unprotected_install() {
        // installPlugin() selector without access control
        let bytecode = vec![
            0xa1, 0x5c, 0x3d, 0x4f, // installPlugin() selector
            // No CALLER + EQ check
        ];
        
        let detector = Erc6900PluginDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            Erc6900PluginVulnerabilityType::UnprotectedPluginInstall
        )));
    }
    
    #[test]
    fn test_storage_conflict() {
        // DELEGATECALL without namespace
        let bytecode = vec![
            0xF4, // DELEGATECALL (no prior KECCAK256 for namespace)
        ];
        
        let detector = Erc6900PluginDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            Erc6900PluginVulnerabilityType::PluginStorageConflict
        )));
    }
}
