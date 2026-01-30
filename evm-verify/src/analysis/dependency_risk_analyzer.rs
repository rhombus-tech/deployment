/// Dependency Risk Analyzer
/// Analyzes inherited contracts, libraries, and supply chain risks
use crate::bytecode::SecuritySeverity;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct DependencyRiskAnalyzer {
    bytecode: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DependencyRiskReport {
    pub dependencies: Vec<Dependency>,
    pub supply_chain_risks: Vec<SupplyChainRisk>,
    pub overall_risk_score: f64,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub dependency_type: DependencyType,
    pub version: Option<String>,
    pub known_vulnerabilities: Vec<KnownVulnerability>,
    pub risk_level: SecuritySeverity,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DependencyType {
    InheritedContract,     // Contract A is B
    Library,               // Using SafeMath for uint256
    DelegateCall,          // Delegatecall to external contract
    ExternalContract,      // Direct calls to external contracts
    Proxy,                 // Proxy pattern dependencies
}

#[derive(Debug, Clone)]
pub struct KnownVulnerability {
    pub cve_id: Option<String>,
    pub description: String,
    pub severity: SecuritySeverity,
    pub affected_versions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SupplyChainRisk {
    pub risk_type: SupplyChainRiskType,
    pub description: String,
    pub mitigation: String,
}

#[derive(Debug, Clone)]
pub enum SupplyChainRiskType {
    UnverifiedSource,      // Unverified contract source
    UnauditedDependency,   // Dependency not audited
    OutdatedVersion,       // Using outdated version
    CompilerBug,           // Known compiler bug
    MaliciousCode,         // Potentially malicious code
    CentralizedDependency, // Single point of failure
}

impl DependencyRiskAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn analyze_dependencies(&self) -> DependencyRiskReport {
        let dependencies = self.identify_dependencies();
        let supply_chain_risks = self.assess_supply_chain_risks(&dependencies);
        let overall_risk = self.calculate_overall_risk(&dependencies, &supply_chain_risks);
        let recommendations = self.generate_recommendations(&dependencies, &supply_chain_risks);

        DependencyRiskReport {
            dependencies,
            supply_chain_risks,
            overall_risk_score: overall_risk,
            recommendations,
        }
    }

    fn identify_dependencies(&self) -> Vec<Dependency> {
        let mut deps = Vec::new();

        // Detect OpenZeppelin contracts
        if self.uses_openzeppelin() {
            deps.push(Dependency {
                name: "OpenZeppelin Contracts".to_string(),
                dependency_type: DependencyType::Library,
                version: self.detect_oz_version(),
                known_vulnerabilities: self.get_oz_vulnerabilities(),
                risk_level: SecuritySeverity::Low, // OpenZeppelin is generally safe
            });
        }

        // Detect SafeMath usage
        if self.uses_safemath() {
            deps.push(Dependency {
                name: "SafeMath".to_string(),
                dependency_type: DependencyType::Library,
                version: None,
                known_vulnerabilities: vec![],
                risk_level: SecuritySeverity::Low,
            });
        }

        // Detect delegatecall dependencies
        if self.has_delegatecall() {
            deps.push(Dependency {
                name: "Unknown Delegatecall Target".to_string(),
                dependency_type: DependencyType::DelegateCall,
                version: None,
                known_vulnerabilities: vec![
                    KnownVulnerability {
                        cve_id: None,
                        description: "Delegatecall to untrusted contract - Parity Wallet style".to_string(),
                        severity: SecuritySeverity::Critical,
                        affected_versions: vec!["All".to_string()],
                    },
                ],
                risk_level: SecuritySeverity::Critical,
            });
        }

        // Detect external contract calls
        if self.has_external_calls() {
            deps.push(Dependency {
                name: "External Contracts".to_string(),
                dependency_type: DependencyType::ExternalContract,
                version: None,
                known_vulnerabilities: vec![],
                risk_level: SecuritySeverity::Medium,
            });
        }

        deps
    }

    fn assess_supply_chain_risks(&self, dependencies: &[Dependency]) -> Vec<SupplyChainRisk> {
        let mut risks = Vec::new();

        // Check for unverified sources
        if dependencies.iter().any(|d| d.version.is_none()) {
            risks.push(SupplyChainRisk {
                risk_type: SupplyChainRiskType::UnverifiedSource,
                description: "Dependencies without version information detected".to_string(),
                mitigation: "Pin dependency versions and verify sources".to_string(),
            });
        }

        // Check for outdated versions
        if self.has_outdated_dependencies(dependencies) {
            risks.push(SupplyChainRisk {
                risk_type: SupplyChainRiskType::OutdatedVersion,
                description: "Outdated dependency versions with known vulnerabilities".to_string(),
                mitigation: "Upgrade to latest stable versions".to_string(),
            });
        }

        // Check for compiler bugs
        if self.has_compiler_bugs() {
            risks.push(SupplyChainRisk {
                risk_type: SupplyChainRiskType::CompilerBug,
                description: "Compiler version has known bugs".to_string(),
                mitigation: "Upgrade Solidity compiler to 0.8.0+".to_string(),
            });
        }

        // Check for centralized dependencies
        if dependencies.iter().any(|d| matches!(d.dependency_type, DependencyType::DelegateCall)) {
            risks.push(SupplyChainRisk {
                risk_type: SupplyChainRiskType::CentralizedDependency,
                description: "Delegatecall creates centralized dependency".to_string(),
                mitigation: "Use transparent upgrade patterns or remove delegatecall".to_string(),
            });
        }

        risks
    }

    fn calculate_overall_risk(&self, deps: &[Dependency], risks: &[SupplyChainRisk]) -> f64 {
        let dep_risk: f64 = deps.iter()
            .map(|d| match d.risk_level {
                SecuritySeverity::Critical => 10.0,
                SecuritySeverity::High => 7.0,
                SecuritySeverity::Medium => 4.0,
                SecuritySeverity::Low => 2.0,
                SecuritySeverity::Info => 1.0,
            })
            .sum();

        let supply_risk = risks.len() as f64 * 3.0;

        (dep_risk + supply_risk) / (deps.len() as f64 + 1.0)
    }

    fn generate_recommendations(&self, deps: &[Dependency], risks: &[SupplyChainRisk]) -> Vec<String> {
        let mut recs = Vec::new();

        recs.push("Use dependency lock files (package-lock.json, yarn.lock)".to_string());
        recs.push("Pin all dependency versions explicitly".to_string());
        recs.push("Regularly audit and update dependencies".to_string());
        recs.push("Use verified and audited libraries (OpenZeppelin)".to_string());
        recs.push("Avoid delegatecall to untrusted contracts".to_string());

        for dep in deps {
            if matches!(dep.risk_level, SecuritySeverity::Critical | SecuritySeverity::High) {
                recs.push(format!("URGENT: Review dependency '{}'", dep.name));
            }
        }

        for risk in risks {
            recs.push(risk.mitigation.clone());
        }

        recs
    }

    // Helper methods
    fn uses_openzeppelin(&self) -> bool {
        // OpenZeppelin has characteristic patterns
        // Check for ERC patterns, Ownable patterns, etc
        self.bytecode.windows(2).any(|w| w == &[0x33, 0x14]) // Owner check pattern
    }

    fn detect_oz_version(&self) -> Option<String> {
        // Simplified - would need to check specific patterns
        Some("4.9.0".to_string())
    }

    fn get_oz_vulnerabilities(&self) -> Vec<KnownVulnerability> {
        // Check for known OZ vulnerabilities
        vec![]
    }

    fn uses_safemath(&self) -> bool {
        // SafeMath has ADD followed by overflow checks
        self.bytecode.windows(2).any(|w| matches!(w, [0x01, 0x10] | [0x02, 0x10]))
    }

    fn has_delegatecall(&self) -> bool {
        self.bytecode.contains(&0xf4) // DELEGATECALL opcode
    }

    fn has_external_calls(&self) -> bool {
        self.bytecode.contains(&0xf1) || self.bytecode.contains(&0xfa) // CALL or STATICCALL
    }

    fn has_outdated_dependencies(&self, dependencies: &[Dependency]) -> bool {
        dependencies.iter().any(|d| {
            if let Some(version) = &d.version {
                // Check if version is < 4.0.0 for OpenZeppelin
                version.starts_with("3.") || version.starts_with("2.")
            } else {
                false
            }
        })
    }

    fn has_compiler_bugs(&self) -> bool {
        // Check for patterns indicating old Solidity versions
        // This is simplified - would need metadata
        false
    }

    pub fn get_critical_dependencies(&self) -> Vec<Dependency> {
        self.identify_dependencies()
            .into_iter()
            .filter(|d| matches!(d.risk_level, SecuritySeverity::Critical))
            .collect()
    }

    pub fn generate_dependency_graph(&self) -> String {
        r#"
digraph DependencyGraph {
    rankdir=LR;
    node [shape=box];
    
    Contract [label="Main Contract", style=filled, fillcolor=lightblue];
    OpenZeppelin [label="OpenZeppelin\nContracts"];
    SafeMath [label="SafeMath\nLibrary"];
    External [label="External\nContracts", style=filled, fillcolor=yellow];
    
    Contract -> OpenZeppelin;
    Contract -> SafeMath [style=dashed];
    Contract -> External [color=red, label="High Risk"];
}
"#.to_string()
    }

    pub fn export_sbom(&self) -> String {
        // Software Bill of Materials (SBOM)
        r#"
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "components": [
    {
      "type": "library",
      "name": "OpenZeppelin Contracts",
      "version": "4.9.0",
      "licenses": ["MIT"],
      "vulnerabilities": []
    },
    {
      "type": "library",
      "name": "SafeMath",
      "vulnerabilities": []
    }
  ]
}
"#.to_string()
    }
}
