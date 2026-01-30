use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Advanced Permission Escalation Detection
/// 
/// Detects multi-step permission escalation attacks:
/// 1. Chained permission grants leading to admin
/// 2. Temporary permission abuse
/// 3. Role combination exploits
/// 4. Delegate-then-escalate patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PermissionEscalationAdvancedVulnerability {
    /// Critical: Multi-step escalation to admin
    MultiStepEscalationToAdmin {
        description: String,
        escalation_chain: Vec<String>,
        confidence: f32,
    },
    /// High: Temporary permission can be made permanent
    TemporaryPermissionPermanent {
        description: String,
        location: usize,
    },
    /// High: Role combination grants excessive permissions
    RoleCombinationEscalation {
        description: String,
        roles: Vec<String>,
        location: usize,
    },
    /// Critical: Delegate authorization allows escalation
    DelegateEscalationPath {
        description: String,
        location: usize,
        escalation_type: String,
    },
}

pub struct PermissionEscalationAdvancedDetector {
    bytecode: Vec<u8>,
}

impl PermissionEscalationAdvancedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PermissionEscalationAdvancedVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Build permission graph
        let permission_graph = self.build_permission_graph();
        
        // Pattern 1: Multi-step escalation paths
        let escalation_paths = self.find_escalation_paths(&permission_graph);
        
        for path in escalation_paths {
            if path.len() >= 2 && path.last().map_or(false, |r| r.contains("admin")) {
                vulnerabilities.push(PermissionEscalationAdvancedVulnerability::MultiStepEscalationToAdmin {
                    description: format!("{} step escalation path to admin role", path.len()),
                    escalation_chain: path.clone(),
                    confidence: 0.90,
                });
            }
        }
        
        // Pattern 2: Temporary permissions
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if self.is_temporary_permission_grant(i) {
                let can_become_permanent = self.temporary_can_become_permanent(i, i + 150);
                
                if can_become_permanent {
                    vulnerabilities.push(PermissionEscalationAdvancedVulnerability::TemporaryPermissionPermanent {
                        description: "Temporary permission lacks revocation enforcement".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Pattern 3: Role combination exploits
        let role_combinations = self.find_dangerous_role_combinations();
        
        for (roles, location) in role_combinations {
            if roles.len() >= 2 {
                vulnerabilities.push(PermissionEscalationAdvancedVulnerability::RoleCombinationEscalation {
                    description: "Combination of roles grants admin-level permissions".to_string(),
                    roles: roles.clone(),
                    location,
                });
            }
        }
        
        // Pattern 4: Delegate escalation
        for i in 0..self.bytecode.len().saturating_sub(120) {
            if self.is_delegation_function(i) {
                if let Some(escalation_type) = self.delegation_allows_escalation(i, i + 120) {
                    vulnerabilities.push(PermissionEscalationAdvancedVulnerability::DelegateEscalationPath {
                        description: "Delegation mechanism allows permission escalation".to_string(),
                        location: i,
                        escalation_type,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn build_permission_graph(&self) -> HashMap<String, Vec<String>> {
        let mut graph = HashMap::new();
        
        // Find all grantRole patterns and build dependency graph
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_grant_role_function(i) {
                let (from_role, to_role) = self.extract_role_relationship(i, i + 100);
                
                graph.entry(from_role.clone())
                    .or_insert_with(Vec::new)
                    .push(to_role);
            }
        }
        
        graph
    }
    
    fn find_escalation_paths(&self, graph: &HashMap<String, Vec<String>>) -> Vec<Vec<String>> {
        let mut paths = Vec::new();
        
        // DFS to find paths from user roles to admin
        for start_role in graph.keys() {
            if !start_role.contains("admin") {
                let mut current_path = vec![start_role.clone()];
                let mut visited = HashSet::new();
                self.dfs_escalation(graph, start_role, &mut current_path, &mut visited, &mut paths);
            }
        }
        
        paths
    }
    
    fn dfs_escalation(
        &self,
        graph: &HashMap<String, Vec<String>>,
        current: &str,
        path: &mut Vec<String>,
        visited: &mut HashSet<String>,
        all_paths: &mut Vec<Vec<String>>,
    ) {
        if visited.contains(current) {
            return;
        }
        
        visited.insert(current.to_string());
        
        if current.contains("admin") {
            all_paths.push(path.clone());
            return;
        }
        
        if let Some(next_roles) = graph.get(current) {
            for next_role in next_roles {
                path.push(next_role.clone());
                self.dfs_escalation(graph, next_role, path, visited, all_paths);
                path.pop();
            }
        }
        
        visited.remove(current);
    }
    
    fn is_grant_role_function(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        // grantRole selector: 0x2f2ff15d
        self.bytecode[location..location + 20].windows(4).any(|w| {
            w[0] == 0x63 && w[1] == 0x2f && w[2] == 0x2f && w[3] == 0xf1
        })
    }
    
    fn extract_role_relationship(&self, start: usize, end: usize) -> (String, String) {
        // Simplified role extraction
        let range_end = end.min(self.bytecode.len());
        
        // Count PUSH operations to identify roles
        let push_count = self.bytecode[start..range_end]
            .iter()
            .filter(|&&b| b >= 0x60 && b <= 0x7f)
            .count();
        
        if push_count >= 2 {
            ("user_role".to_string(), "elevated_role".to_string())
        } else {
            ("unknown".to_string(), "unknown".to_string())
        }
    }
    
    fn is_temporary_permission_grant(&self, location: usize) -> bool {
        if location + 50 > self.bytecode.len() {
            return false;
        }
        
        // Temporary permissions include expiry time
        let has_timestamp = self.bytecode[location..location + 50]
            .iter()
            .any(|&b| b == 0x42); // TIMESTAMP
        
        let has_grant = self.is_grant_role_function(location);
        
        has_grant && has_timestamp
    }
    
    fn temporary_can_become_permanent(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Check if expiry can be bypassed or extended indefinitely
        let has_expiry_check = self.bytecode[start..range_end].windows(4).any(|w| {
            w[0] == 0x42 && // TIMESTAMP
            w[1] == 0x10 && // LT
            w[2] == 0x15 && // ISZERO
            w[3] == 0xfd    // REVERT
        });
        
        let has_extend_function = self.bytecode[start..range_end].windows(4).any(|w| {
            w[0] == 0x63 && w[1] == 0x65 // extend pattern
        });
        
        !has_expiry_check || has_extend_function
    }
    
    fn find_dangerous_role_combinations(&self) -> Vec<(Vec<String>, usize)> {
        let mut combinations = Vec::new();
        
        // Find functions that check multiple roles with OR logic
        for i in 0..self.bytecode.len().saturating_sub(100) {
            let role_checks = self.count_role_checks(i, i + 100);
            
            if role_checks >= 2 {
                let has_or_logic = self.has_or_logic(i, i + 100);
                
                if has_or_logic {
                    let roles = (0..role_checks)
                        .map(|idx| format!("role_{}", idx))
                        .collect();
                    combinations.push((roles, i));
                }
            }
        }
        
        combinations
    }
    
    fn count_role_checks(&self, start: usize, end: usize) -> usize {
        let range_end = end.min(self.bytecode.len());
        
        // Count hasRole or similar checks
        self.bytecode[start..range_end]
            .windows(4)
            .filter(|w| {
                w[0] == 0x63 && (w[1] == 0x91 || w[1] == 0x21) // hasRole patterns
            })
            .count()
    }
    
    fn has_or_logic(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // OR logic uses ISZERO ISZERO pattern or direct OR
        self.bytecode[start..range_end]
            .windows(2)
            .any(|w| w[0] == 0x15 && w[1] == 0x15) || // Double ISZERO
        self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0x17) // OR opcode
    }
    
    fn is_delegation_function(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        // delegate() or delegateCall patterns
        self.bytecode[location..location + 20].windows(4).any(|w| {
            w[0] == 0x63 && (w[1] == 0x5c || w[1] == 0xf4)
        })
    }
    
    fn delegation_allows_escalation(&self, start: usize, end: usize) -> Option<String> {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return None;
        }
        
        // Check if delegation grants more permissions than delegator has
        let has_permission_amplification = self.bytecode[start..range_end]
            .windows(10)
            .any(|w| {
                // Multiple role grants in delegation
                w.iter().filter(|&&b| b == 0x55).count() > 1 // Multiple SSTOREs
            });
        
        if has_permission_amplification {
            Some("permission_amplification".to_string())
        } else {
            None
        }
    }
}
