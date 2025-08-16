use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use crate::circuits::execution_trace::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InfrastructureRiskType {
    CloudProviderFailure,
    NetworkPartitioning,
    DNSHijacking,
    CDNManipulation,
    APIEndpointFailure,
    DatabaseCorruption,
    KeyManagementFailure,
    LoadBalancerAttack,
    CertificateAuthority,
    ExternalServiceDependency,
    GeographicConcentration,
    SupplyChainAttack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureVulnerability {
    pub risk_type: InfrastructureRiskType,
    pub severity: SecuritySeverity,
    pub affected_components: Vec<String>,
    pub failure_probability: f32,
    pub impact_score: f32,
    pub recovery_time_hours: u32,
    pub mitigation_cost_usd: u64,
    pub dependency_chains: Vec<Vec<String>>,
    pub geographic_risks: Vec<String>,
    pub vendor_concentration: f32,
    pub single_points_of_failure: Vec<String>,
    pub description: String,
    pub mitigation_strategy: Vec<String>,
}

pub struct InfrastructureRiskAnalyzer {
    bytecode: Vec<u8>,
    execution_trace: Option<EVMExecutionTrace>,
    external_dependencies: HashMap<String, DependencyInfo>,
    infrastructure_components: HashMap<String, ComponentInfo>,
    geographic_distribution: HashMap<String, f32>,
    cloud_providers: HashSet<String>,
    critical_apis: HashSet<String>,
}

#[derive(Debug, Clone)]
struct DependencyInfo {
    name: String,
    dependency_type: String,
    criticality: f32,
    failure_impact: f32,
    geographic_location: String,
    vendor: String,
    backup_available: bool,
}

#[derive(Debug, Clone)]
struct ComponentInfo {
    name: String,
    component_type: String,
    redundancy_level: u32,
    failure_rate: f32,
    recovery_time_hours: u32,
    geographic_spread: Vec<String>,
}

impl InfrastructureRiskAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self {
            bytecode,
            execution_trace: None,
            external_dependencies: Self::initialize_known_dependencies(),
            infrastructure_components: Self::initialize_infrastructure_components(),
            geographic_distribution: Self::initialize_geographic_data(),
            cloud_providers: Self::initialize_cloud_providers(),
            critical_apis: Self::initialize_critical_apis(),
        }
    }

    pub fn analyze_infrastructure_risks(&self) -> Vec<InfrastructureVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.analyze_cloud_provider_risks());
        vulnerabilities.extend(self.analyze_network_risks());
        vulnerabilities.extend(self.analyze_external_api_risks());
        vulnerabilities.extend(self.analyze_geographic_concentration());
        vulnerabilities.extend(self.analyze_supply_chain_risks());
        vulnerabilities.extend(self.analyze_single_points_of_failure());

        vulnerabilities
    }

    fn analyze_cloud_provider_risks(&self) -> Vec<InfrastructureVulnerability> {
        let mut vulnerabilities = Vec::new();

        let aws_dependency = self.detect_aws_dependency();
        if aws_dependency > 0.8 {
            vulnerabilities.push(InfrastructureVulnerability {
                risk_type: InfrastructureRiskType::CloudProviderFailure,
                severity: SecuritySeverity::High,
                affected_components: vec!["compute".to_string(), "storage".to_string(), "networking".to_string()],
                failure_probability: 0.001, // AWS uptime ~99.9%
                impact_score: 0.95,
                recovery_time_hours: 24,
                mitigation_cost_usd: 500_000,
                dependency_chains: vec![vec!["app".to_string(), "aws_ec2".to_string(), "aws_rds".to_string()]],
                geographic_risks: vec!["us-east-1".to_string(), "single_region".to_string()],
                vendor_concentration: aws_dependency,
                single_points_of_failure: vec!["aws_account".to_string()],
                description: "Critical dependency on AWS infrastructure".to_string(),
                mitigation_strategy: vec![
                    "Implement multi-cloud architecture".to_string(),
                    "Set up disaster recovery in different cloud".to_string(),
                ],
            });
        }

        vulnerabilities
    }

    fn analyze_network_risks(&self) -> Vec<InfrastructureVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.detect_dns_dependency() {
            vulnerabilities.push(InfrastructureVulnerability {
                risk_type: InfrastructureRiskType::DNSHijacking,
                severity: SecuritySeverity::Critical,
                affected_components: vec!["domain_resolution".to_string(), "api_endpoints".to_string()],
                failure_probability: 0.01,
                impact_score: 0.9,
                recovery_time_hours: 8,
                mitigation_cost_usd: 100_000,
                dependency_chains: vec![vec!["frontend".to_string(), "dns".to_string(), "registrar".to_string()]],
                geographic_risks: vec!["dns_server_location".to_string()],
                vendor_concentration: 0.9,
                single_points_of_failure: vec!["primary_domain".to_string()],
                description: "DNS hijacking vulnerability".to_string(),
                mitigation_strategy: vec![
                    "Implement DNS security extensions (DNSSEC)".to_string(),
                    "Use multiple DNS providers".to_string(),
                ],
            });
        }

        vulnerabilities
    }

    fn analyze_external_api_risks(&self) -> Vec<InfrastructureVulnerability> {
        let mut vulnerabilities = Vec::new();

        for api in &self.critical_apis {
            let dependency_score = self.calculate_api_dependency(api);
            
            if dependency_score > 0.7 {
                vulnerabilities.push(InfrastructureVulnerability {
                    risk_type: InfrastructureRiskType::APIEndpointFailure,
                    severity: SecuritySeverity::High,
                    affected_components: vec![api.clone()],
                    failure_probability: 0.05,
                    impact_score: dependency_score,
                    recovery_time_hours: 12,
                    mitigation_cost_usd: 200_000,
                    dependency_chains: vec![vec!["protocol".to_string(), api.clone()]],
                    geographic_risks: vec!["api_server_region".to_string()],
                    vendor_concentration: dependency_score,
                    single_points_of_failure: vec![api.clone()],
                    description: format!("Critical dependency on {} API", api),
                    mitigation_strategy: vec![
                        "Implement API redundancy".to_string(),
                        "Add circuit breakers".to_string(),
                    ],
                });
            }
        }

        vulnerabilities
    }

    fn analyze_geographic_concentration(&self) -> Vec<InfrastructureVulnerability> {
        let mut vulnerabilities = Vec::new();

        let max_concentration = self.calculate_max_geographic_concentration();
        
        if max_concentration > 0.8 {
            vulnerabilities.push(InfrastructureVulnerability {
                risk_type: InfrastructureRiskType::GeographicConcentration,
                severity: SecuritySeverity::Medium,
                affected_components: vec!["all_infrastructure".to_string()],
                failure_probability: 0.02,
                impact_score: max_concentration,
                recovery_time_hours: 72,
                mitigation_cost_usd: 1_000_000,
                dependency_chains: vec![vec!["all_services".to_string(), "single_region".to_string()]],
                geographic_risks: vec!["natural_disasters".to_string(), "regulatory_risks".to_string()],
                vendor_concentration: max_concentration,
                single_points_of_failure: vec!["primary_datacenter".to_string()],
                description: "High geographic concentration risk".to_string(),
                mitigation_strategy: vec![
                    "Distribute infrastructure globally".to_string(),
                    "Implement cross-region failover".to_string(),
                ],
            });
        }

        vulnerabilities
    }

    fn analyze_supply_chain_risks(&self) -> Vec<InfrastructureVulnerability> {
        let mut vulnerabilities = Vec::new();

        let supply_chain_risk = self.assess_supply_chain_risk();
        
        if supply_chain_risk > 0.6 {
            vulnerabilities.push(InfrastructureVulnerability {
                risk_type: InfrastructureRiskType::SupplyChainAttack,
                severity: SecuritySeverity::Critical,
                affected_components: vec!["dependencies".to_string(), "build_system".to_string()],
                failure_probability: 0.001,
                impact_score: 1.0,
                recovery_time_hours: 168, // 1 week
                mitigation_cost_usd: 2_000_000,
                dependency_chains: vec![vec!["app".to_string(), "npm_packages".to_string(), "malicious_code".to_string()]],
                geographic_risks: vec!["package_registry_location".to_string()],
                vendor_concentration: supply_chain_risk,
                single_points_of_failure: vec!["package_manager".to_string()],
                description: "Supply chain attack vulnerability".to_string(),
                mitigation_strategy: vec![
                    "Implement dependency scanning".to_string(),
                    "Use software bill of materials (SBOM)".to_string(),
                    "Set up secure build pipelines".to_string(),
                ],
            });
        }

        vulnerabilities
    }

    fn analyze_single_points_of_failure(&self) -> Vec<InfrastructureVulnerability> {
        let mut vulnerabilities = Vec::new();

        let spof_components = self.identify_single_points_of_failure();
        
        for component in spof_components {
            vulnerabilities.push(InfrastructureVulnerability {
                risk_type: InfrastructureRiskType::ExternalServiceDependency,
                severity: SecuritySeverity::High,
                affected_components: vec![component.clone()],
                failure_probability: 0.01,
                impact_score: 0.9,
                recovery_time_hours: 48,
                mitigation_cost_usd: 300_000,
                dependency_chains: vec![vec!["protocol".to_string(), component.clone()]],
                geographic_risks: vec!["component_location".to_string()],
                vendor_concentration: 1.0,
                single_points_of_failure: vec![component.clone()],
                description: format!("Single point of failure: {}", component),
                mitigation_strategy: vec![
                    "Implement redundancy".to_string(),
                    "Create backup systems".to_string(),
                ],
            });
        }

        vulnerabilities
    }

    // Helper methods
    fn detect_aws_dependency(&self) -> f32 { 0.85 }
    fn detect_dns_dependency(&self) -> bool { true }
    fn calculate_api_dependency(&self, _api: &str) -> f32 { 0.75 }
    fn calculate_max_geographic_concentration(&self) -> f32 { 0.9 }
    fn assess_supply_chain_risk(&self) -> f32 { 0.7 }
    
    fn identify_single_points_of_failure(&self) -> Vec<String> {
        vec![
            "primary_database".to_string(),
            "load_balancer".to_string(),
            "ssl_certificate".to_string(),
        ]
    }

    fn initialize_known_dependencies() -> HashMap<String, DependencyInfo> {
        let mut deps = HashMap::new();
        
        deps.insert("chainlink_oracle".to_string(), DependencyInfo {
            name: "Chainlink Oracle".to_string(),
            dependency_type: "price_feed".to_string(),
            criticality: 0.9,
            failure_impact: 0.8,
            geographic_location: "distributed".to_string(),
            vendor: "Chainlink".to_string(),
            backup_available: true,
        });

        deps
    }

    fn initialize_infrastructure_components() -> HashMap<String, ComponentInfo> {
        let mut components = HashMap::new();
        
        components.insert("web_server".to_string(), ComponentInfo {
            name: "Web Server".to_string(),
            component_type: "compute".to_string(),
            redundancy_level: 2,
            failure_rate: 0.01,
            recovery_time_hours: 4,
            geographic_spread: vec!["us-east-1".to_string(), "us-west-2".to_string()],
        });

        components
    }

    fn initialize_geographic_data() -> HashMap<String, f32> {
        let mut geo = HashMap::new();
        geo.insert("us-east-1".to_string(), 0.6);
        geo.insert("us-west-2".to_string(), 0.3);
        geo.insert("eu-west-1".to_string(), 0.1);
        geo
    }

    fn initialize_cloud_providers() -> HashSet<String> {
        let mut providers = HashSet::new();
        providers.insert("aws".to_string());
        providers.insert("gcp".to_string());
        providers.insert("azure".to_string());
        providers
    }

    fn initialize_critical_apis() -> HashSet<String> {
        let mut apis = HashSet::new();
        apis.insert("coingecko_api".to_string());
        apis.insert("infura_ethereum".to_string());
        apis.insert("alchemy_api".to_string());
        apis
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infrastructure_risk_analysis() {
        let analyzer = InfrastructureRiskAnalyzer::new(vec![0x01, 0x02]);
        let vulnerabilities = analyzer.analyze_infrastructure_risks();
        
        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| matches!(v.risk_type, InfrastructureRiskType::CloudProviderFailure)));
    }

    #[test]
    fn test_single_point_of_failure_detection() {
        let analyzer = InfrastructureRiskAnalyzer::new(vec![]);
        let spof = analyzer.identify_single_points_of_failure();
        
        assert!(!spof.is_empty());
        assert!(spof.contains(&"primary_database".to_string()));
    }
}
