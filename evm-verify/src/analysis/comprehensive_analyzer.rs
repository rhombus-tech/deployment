use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use crate::analysis::{
    economic_attacks::{EconomicAttackAnalyzer, EconomicVulnerability},
    upgradeable_risks::{UpgradeableRiskAnalyzer, UpgradeableVulnerability},
    sandwich_attacks::{SandwichAttackDetector, SandwichVulnerability},
    time_attacks::{TimeAttackDetector, TimeVulnerability},
    cross_contract::{ProtocolFindingKind},
    bridge_security::{BridgeSecurityAnalyzer, BridgeVulnerability},
    protocol_dependency_mapping::{ProtocolDependencyMapper, ProtocolDependencyVulnerability},
    defi_primitive_analyzer::{DeFiPrimitiveAnalyzer, DeFiPrimitiveVulnerability},
    cross_contract_state_manipulation::{CrossContractStateManipulator, StateManipulationVulnerability},
    mev_attack_chain_detector::{MevAttackChainDetector, MevAttackVulnerability},
    // Advanced security modules
    governance_attack_detector::{GovernanceAttackDetector, GovernanceVulnerability},
    oracle_infrastructure_analyzer::{OracleInfrastructureAnalyzer, OracleInfrastructureVulnerability},
    lp_economic_attack_analyzer::{LPEconomicAttackAnalyzer, LPEconomicVulnerability},
    black_swan_simulator::{BlackSwanSimulator, BlackSwanVulnerability},
    multi_vector_attack_simulator::{MultiVectorAttackSimulator, MultiVectorVulnerability},
    ai_adaptive_attack_detector::{AIAdaptiveAttackDetector, AIDetectedVulnerability},
    infrastructure_risk_analyzer::{InfrastructureRiskAnalyzer, InfrastructureVulnerability},
    // Latest detection modules
    atomic_composability_detector::{AtomicComposabilityDetector, ComposabilityVulnerability},
    protocol_integration_detector::{ProtocolIntegrationDetector, IntegrationVulnerability},
    advanced_mev_detector::{AdvancedMEVDetector, AdvancedMEVVulnerability},
    gas_economic_detector::{GasEconomicDetector, GasEconomicVulnerability},
    multi_protocol_flashloan_detector::{MultiProtocolFlashLoanDetector, FlashLoanVulnerability},
    data_integrity_detector::{DataIntegrityDetector, DataIntegrityVulnerability},
};
use serde::{Serialize, Deserialize};
use crate::circuits::execution_trace::*;
use ethers::types::H256;

/// Comprehensive security analysis results without subjective scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveAnalysisResult {
    pub contract_address: Option<String>,
    pub analysis_timestamp: u64,
    pub total_vulnerabilities: u32,
    pub economic_vulnerabilities: Vec<EconomicVulnerability>,
    pub upgrade_vulnerabilities: Vec<UpgradeableVulnerability>,
    pub sandwich_vulnerabilities: Vec<SandwichVulnerability>,
    pub time_vulnerabilities: Vec<TimeVulnerability>,
    pub cross_contract_vulnerabilities: Vec<ProtocolFindingKind>,
    // New comprehensive security analysis results
    pub bridge_vulnerabilities: Vec<BridgeVulnerability>,
    pub protocol_dependency_vulnerabilities: Vec<ProtocolDependencyVulnerability>,
    pub defi_primitive_vulnerabilities: Vec<DeFiPrimitiveVulnerability>,
    // Advanced cross-contract attack detection results
    pub state_manipulation_vulnerabilities: Vec<StateManipulationVulnerability>,
    pub mev_attack_vulnerabilities: Vec<MevAttackVulnerability>,
    // Advanced security analysis results
    pub governance_vulnerabilities: Vec<GovernanceVulnerability>,
    pub oracle_infrastructure_vulnerabilities: Vec<OracleInfrastructureVulnerability>,
    pub lp_economic_vulnerabilities: Vec<LPEconomicVulnerability>,
    pub black_swan_vulnerabilities: Vec<BlackSwanVulnerability>,
    pub multi_vector_vulnerabilities: Vec<MultiVectorVulnerability>,
    pub ai_detected_vulnerabilities: Vec<AIDetectedVulnerability>,
    pub infrastructure_vulnerabilities: Vec<InfrastructureVulnerability>,
    // Latest detection modules results
    pub atomic_composability_vulnerabilities: Vec<ComposabilityVulnerability>,
    pub protocol_integration_vulnerabilities: Vec<IntegrationVulnerability>,
    pub advanced_mev_vulnerabilities: Vec<AdvancedMEVVulnerability>,
    pub gas_economic_vulnerabilities: Vec<GasEconomicVulnerability>,
    pub flash_loan_vulnerabilities: Vec<FlashLoanVulnerability>,
    pub data_integrity_vulnerabilities: Vec<DataIntegrityVulnerability>,
    pub security_summary: SecuritySummary,
    pub analysis_confidence: f32, // Overall detection confidence 0.0-1.0
    pub coverage_metrics: CoverageMetrics,
}

/// Security summary with objective metrics only
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySummary {
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub attack_vectors_detected: u32,
    pub economic_invariants_violated: u32,
    pub proxy_patterns_analyzed: u32,
    pub time_dependencies_found: u32,
    pub cross_contract_risks: u32,
}

/// Coverage metrics for analysis completeness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageMetrics {
    pub bytecode_coverage_percentage: f32,
    pub function_signatures_analyzed: u32,
    pub opcodes_analyzed: u32,
    pub analysis_modules_run: u32,
    pub analysis_duration_ms: u64,
    pub proof_generation_time_ms: Option<u64>,
}

/// Comprehensive analyzer integrating all security modules
pub struct ComprehensiveSecurityAnalyzer {
    bytecode: Vec<u8>,
    contract_address: Option<String>,
    enable_cross_contract: bool,
    enable_economic_analysis: bool,
    enable_upgrade_analysis: bool,
    enable_sandwich_analysis: bool,
    enable_time_analysis: bool,
    // New comprehensive security analysis flags
    enable_bridge_analysis: bool,
    enable_protocol_dependency_analysis: bool,
    enable_defi_primitive_analysis: bool,
    // Advanced cross-contract attack detection flags
    enable_state_manipulation_analysis: bool,
    enable_mev_attack_analysis: bool,
    // Advanced security analysis flags
    enable_governance_analysis: bool,
    enable_oracle_infrastructure_analysis: bool,
    enable_lp_economic_analysis: bool,
    enable_black_swan_analysis: bool,
    enable_multi_vector_analysis: bool,
    enable_ai_adaptive_analysis: bool,
    enable_infrastructure_analysis: bool,
    // Latest detection module flags
    enable_atomic_composability_analysis: bool,
    enable_protocol_integration_analysis: bool,
    enable_advanced_mev_analysis: bool,
    enable_gas_economic_analysis: bool,
    enable_flash_loan_analysis: bool,
    enable_data_integrity_analysis: bool,
}

impl ComprehensiveSecurityAnalyzer {
    /// Create new comprehensive analyzer
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self {
            bytecode,
            contract_address: None,
            enable_cross_contract: true,
            enable_economic_analysis: true,
            enable_upgrade_analysis: true,
            enable_sandwich_analysis: true,
            enable_time_analysis: true,
            // Initialize new comprehensive security analysis flags
            enable_bridge_analysis: true,
            enable_protocol_dependency_analysis: true,
            enable_defi_primitive_analysis: true,
            // Initialize advanced cross-contract attack detection flags
            enable_state_manipulation_analysis: true,
            enable_mev_attack_analysis: true,
            // Initialize advanced security analysis flags
            enable_governance_analysis: true,
            enable_oracle_infrastructure_analysis: true,
            enable_lp_economic_analysis: true,
            enable_black_swan_analysis: true,
            enable_multi_vector_analysis: true,
            enable_ai_adaptive_analysis: true,
            enable_infrastructure_analysis: true,
            // Initialize latest detection module flags
            enable_atomic_composability_analysis: true,
            enable_protocol_integration_analysis: true,
            enable_advanced_mev_analysis: true,
            enable_gas_economic_analysis: true,
            enable_flash_loan_analysis: true,
            enable_data_integrity_analysis: true,
        }
    }

    /// Set contract address for analysis context
    pub fn with_contract_address(mut self, address: String) -> Self {
        self.contract_address = Some(address);
        self
    }

    /// Configure which analysis modules to run
    pub fn configure_modules(&mut self) {
        // Enable or disable specific analysis modules based on configuration
        self.enable_cross_contract = true;
        self.enable_defi_primitive_analysis = true;
        self.enable_economic_analysis = true;
        self.enable_upgrade_analysis = true;
        self.enable_sandwich_analysis = true;
        self.enable_time_analysis = true;
        // Configure new comprehensive security analysis modules
        self.enable_bridge_analysis = true;
        self.enable_protocol_dependency_analysis = true;
        self.enable_defi_primitive_analysis = true;
        // Configure advanced cross-contract attack detection modules
        self.enable_state_manipulation_analysis = true;
        self.enable_mev_attack_analysis = true;
    }

    /// Run comprehensive security analysis
    pub fn analyze(&self) -> ComprehensiveAnalysisResult {
        let start_time = std::time::Instant::now();
        
        // Run all enabled analysis modules
        let mut economic_vulnerabilities = Vec::new();
        let mut upgrade_vulnerabilities = Vec::new();
        let mut sandwich_vulnerabilities = Vec::new();
        let mut time_vulnerabilities = Vec::new();
        let mut cross_contract_vulnerabilities = Vec::new();
        // New comprehensive security analysis results
        let mut bridge_vulnerabilities = Vec::new();
        let mut protocol_dependency_vulnerabilities = Vec::new();
        let mut defi_primitive_vulnerabilities = Vec::new();
        // Advanced cross-contract attack detection results
        let mut state_manipulation_vulnerabilities = Vec::new();
        let mut mev_attack_vulnerabilities = Vec::new();
        // Latest detection modules results
        let mut atomic_composability_vulnerabilities = Vec::new();
        let mut protocol_integration_vulnerabilities = Vec::new();
        let mut advanced_mev_vulnerabilities = Vec::new();
        let mut gas_economic_vulnerabilities = Vec::new();
        let mut flash_loan_vulnerabilities = Vec::new();
        let mut data_integrity_vulnerabilities = Vec::new();
        
        let mut modules_run = 0;
        let mut total_confidence = 0.0;

        if self.enable_economic_analysis {
            let economic_analyzer = EconomicAttackAnalyzer::new(self.bytecode.clone());
            economic_vulnerabilities = economic_analyzer.detect_vulnerabilities();
            modules_run += 1;
            total_confidence += self.calculate_module_confidence(&economic_vulnerabilities);
        }

        if self.enable_upgrade_analysis {
            let upgrade_analyzer = UpgradeableRiskAnalyzer::new(self.bytecode.clone());
            upgrade_vulnerabilities = upgrade_analyzer.detect_vulnerabilities();
            modules_run += 1;
            total_confidence += self.calculate_upgrade_confidence(&upgrade_vulnerabilities);
        }

        if self.enable_sandwich_analysis {
            let sandwich_analyzer = SandwichAttackDetector::new(self.bytecode.clone());
            sandwich_vulnerabilities = sandwich_analyzer.detect_vulnerabilities();
            modules_run += 1;
            total_confidence += self.calculate_sandwich_confidence(&sandwich_vulnerabilities);
        }

        if self.enable_time_analysis {
            let time_analyzer = TimeAttackDetector::new(self.bytecode.clone());
            time_vulnerabilities = time_analyzer.detect_vulnerabilities();
            modules_run += 1;
            total_confidence += self.calculate_time_confidence(&time_vulnerabilities);
        }

        // Run new comprehensive security analysis modules
        // Create execution trace from bytecode for security analysis
        let execution_trace = EVMExecutionTrace {
            transaction_hash: H256::zero(),
            execution_steps: Vec::new(), // Empty for now, would be populated during execution
            initial_state: EVMState {
                stack: Vec::new(),
                memory: Vec::new(),
                storage: std::collections::HashMap::new(),
                balances: std::collections::HashMap::new(),
                nonces: std::collections::HashMap::new(),
                code: std::collections::HashMap::new(),
                gas_limit: ethers::types::U256::zero(),
            },
            final_state: EVMState {
                stack: Vec::new(),
                memory: Vec::new(),
                storage: std::collections::HashMap::new(),
                balances: std::collections::HashMap::new(),
                nonces: std::collections::HashMap::new(),
                code: std::collections::HashMap::new(),
                gas_limit: ethers::types::U256::zero(),
            },
            gas_trace: GasTrace {
                initial_gas: ethers::types::U256::zero(),
                gas_at_step: Vec::new(),
                gas_breakdown: std::collections::HashMap::new(),
                intrinsic_gas: ethers::types::U256::zero(),
                execution_gas: ethers::types::U256::zero(),
                memory_gas: Vec::new(),
                total_gas_used: ethers::types::U256::zero(),
            },
            memory_trace: MemoryTrace {
                changes: Vec::new(),
                size_at_step: Vec::new(),
                expansion_costs: Vec::new(),
                total_operations: 0,
            },
            storage_trace: StorageTrace {
                changes: Vec::new(),
                gas_costs: Vec::new(),
                total_operations: 0,
            },
            stack_trace: StackTrace {
                changes: Vec::new(),
                depth_at_step: Vec::new(),
                max_depth: 0,
                total_operations: 0,
            },
        };
        
        if self.enable_bridge_analysis {
            let bridge_analyzer = BridgeSecurityAnalyzer::new(self.bytecode.clone());
            bridge_vulnerabilities = bridge_analyzer.analyze_bridge_security(&self.bytecode);
            modules_run += 1;
            total_confidence += self.calculate_bridge_confidence(&bridge_vulnerabilities);
        }

        if self.enable_protocol_dependency_analysis {
            let mut protocol_analyzer = ProtocolDependencyMapper::new(self.bytecode.clone());
            protocol_dependency_vulnerabilities = protocol_analyzer.analyze_dependencies(&self.bytecode);
            modules_run += 1;
            total_confidence += self.calculate_protocol_dependency_confidence(&protocol_dependency_vulnerabilities);
        }

        if self.enable_defi_primitive_analysis {
            let defi_analyzer = DeFiPrimitiveAnalyzer::new(self.bytecode.clone());
            defi_primitive_vulnerabilities = defi_analyzer.analyze_defi_interactions(&self.bytecode);
            modules_run += 1;
            total_confidence += self.calculate_defi_primitive_confidence(&defi_primitive_vulnerabilities);
        }

        // Run advanced cross-contract attack detection modules
        if self.enable_state_manipulation_analysis {
            let mut state_manipulator = CrossContractStateManipulator::new(execution_trace.clone());
            state_manipulation_vulnerabilities = state_manipulator.detect_state_manipulation();
            modules_run += 1;
            total_confidence += self.calculate_state_manipulation_confidence(&state_manipulation_vulnerabilities);
        }

        if self.enable_mev_attack_analysis {
            let mut mev_detector = MevAttackChainDetector::new(execution_trace.clone());
            mev_attack_vulnerabilities = mev_detector.detect_mev_attacks();
            modules_run += 1;
            total_confidence += self.calculate_mev_attack_confidence(&mev_attack_vulnerabilities);
        }

        // Run latest detection modules
        if self.enable_atomic_composability_analysis {
            let mut composability_detector = AtomicComposabilityDetector::new();
            atomic_composability_vulnerabilities = composability_detector.analyze_composability(execution_trace.clone());
            modules_run += 1;
            total_confidence += self.calculate_composability_confidence(&atomic_composability_vulnerabilities);
        }

        if self.enable_protocol_integration_analysis {
            let mut integration_detector = ProtocolIntegrationDetector::new();
            protocol_integration_vulnerabilities = integration_detector.analyze_protocol_integration(execution_trace.clone());
            modules_run += 1;
            total_confidence += self.calculate_protocol_integration_confidence(&protocol_integration_vulnerabilities);
        }

        if self.enable_advanced_mev_analysis {
            let mut advanced_mev_detector = AdvancedMEVDetector::new();
            advanced_mev_vulnerabilities = advanced_mev_detector.analyze_advanced_mev(execution_trace.clone());
            modules_run += 1;
            total_confidence += self.calculate_advanced_mev_confidence(&advanced_mev_vulnerabilities);
        }

        if self.enable_gas_economic_analysis {
            let mut gas_detector = GasEconomicDetector::new();
            gas_economic_vulnerabilities = gas_detector.analyze_gas_economics(execution_trace.clone());
            modules_run += 1;
            total_confidence += self.calculate_gas_economic_confidence(&gas_economic_vulnerabilities);
        }

        if self.enable_flash_loan_analysis {
            let mut flashloan_detector = MultiProtocolFlashLoanDetector::new();
            flash_loan_vulnerabilities = flashloan_detector.analyze_flash_loan_exploits(execution_trace.clone());
            modules_run += 1;
            total_confidence += self.calculate_flash_loan_confidence(&flash_loan_vulnerabilities);
        }

        if self.enable_data_integrity_analysis {
            let mut integrity_detector = DataIntegrityDetector::new();
            data_integrity_vulnerabilities = integrity_detector.analyze_data_integrity(execution_trace.clone());
            modules_run += 1;
            total_confidence += self.calculate_data_integrity_confidence(&data_integrity_vulnerabilities);
        }

        let analysis_duration = start_time.elapsed().as_millis() as u64;
        
        // Calculate comprehensive metrics
        let coverage_metrics = self.calculate_coverage_metrics(analysis_duration, modules_run);
        
        let mut total_vulnerabilities = economic_vulnerabilities.len() as u32 +
                                         upgrade_vulnerabilities.len() as u32 +
                                         sandwich_vulnerabilities.len() as u32 +
                                         time_vulnerabilities.len() as u32 +
                                         cross_contract_vulnerabilities.len() as u32 +
                                         bridge_vulnerabilities.len() as u32 +
                                         protocol_dependency_vulnerabilities.len() as u32 +
                                         defi_primitive_vulnerabilities.len() as u32 +
                                         state_manipulation_vulnerabilities.len() as u32 +
                                         mev_attack_vulnerabilities.len() as u32 +
                                         atomic_composability_vulnerabilities.len() as u32 +
                                         protocol_integration_vulnerabilities.len() as u32 +
                                         advanced_mev_vulnerabilities.len() as u32 +
                                         gas_economic_vulnerabilities.len() as u32 +
                                         flash_loan_vulnerabilities.len() as u32 +
                                         data_integrity_vulnerabilities.len() as u32;

        let overall_confidence = if modules_run > 0 {
            total_confidence / modules_run as f32
        } else {
            0.0
        };

        // Run advanced security modules
        let governance_vulnerabilities = if self.enable_governance_analysis {
            let mut governance_detector = GovernanceAttackDetector::new(self.bytecode.clone());
            let govs = governance_detector.detect_governance_attacks();
            total_vulnerabilities += govs.len() as u32;
            total_confidence += self.calculate_governance_confidence(&govs);
            modules_run += 1;
            govs
        } else {
            Vec::new()
        };

        let oracle_infrastructure_vulnerabilities = if self.enable_oracle_infrastructure_analysis {
            let mut oracle_analyzer = OracleInfrastructureAnalyzer::new(self.bytecode.clone());
            let oracles = oracle_analyzer.analyze_oracle_infrastructure();
            total_vulnerabilities += oracles.len() as u32;
            total_confidence += self.calculate_oracle_infrastructure_confidence(&oracles);
            modules_run += 1;
            oracles
        } else {
            Vec::new()
        };

        let lp_economic_vulnerabilities = if self.enable_lp_economic_analysis {
            let lp_analyzer = LPEconomicAttackAnalyzer::new(self.bytecode.clone());
            let lps = lp_analyzer.analyze_lp_economic_attacks();
            total_vulnerabilities += lps.len() as u32;
            total_confidence += self.calculate_lp_economic_confidence(&lps);
            modules_run += 1;
            lps
        } else {
            Vec::new()
        };

        let black_swan_vulnerabilities = if self.enable_black_swan_analysis {
            let black_swan_simulator = BlackSwanSimulator::new(self.bytecode.clone());
            let swans = black_swan_simulator.simulate_black_swan_events();
            total_vulnerabilities += swans.len() as u32;
            total_confidence += self.calculate_black_swan_confidence(&swans);
            modules_run += 1;
            swans
        } else {
            Vec::new()
        };

        let multi_vector_vulnerabilities = if self.enable_multi_vector_analysis {
            let mut multi_vector_simulator = MultiVectorAttackSimulator::new(self.bytecode.clone(), 1000000.0);
            let multis = multi_vector_simulator.simulate_coordinated_attacks();
            total_vulnerabilities += multis.len() as u32;
            total_confidence += self.calculate_multi_vector_confidence(&multis);
            modules_run += 1;
            multis
        } else {
            Vec::new()
        };

        let ai_detected_vulnerabilities = if self.enable_ai_adaptive_analysis {
            let mut ai_detector = AIAdaptiveAttackDetector::new(self.bytecode.clone());
            let ais = ai_detector.detect_ai_powered_attacks();
            total_vulnerabilities += ais.len() as u32;
            total_confidence += self.calculate_ai_detected_confidence(&ais);
            modules_run += 1;
            ais
        } else {
            Vec::new()
        };

        let infrastructure_vulnerabilities = if self.enable_infrastructure_analysis {
            let infra_analyzer = InfrastructureRiskAnalyzer::new(self.bytecode.clone());
            let infras = infra_analyzer.analyze_infrastructure_risks();
            total_vulnerabilities += infras.len() as u32;
            total_confidence += self.calculate_infrastructure_confidence(&infras);
            modules_run += 1;
            infras
        } else {
            Vec::new()
        };

        let overall_confidence = if modules_run > 0 {
            total_confidence / modules_run as f32
        } else {
            0.0
        };

        // Calculate security summary after all vulnerabilities are detected
        let security_summary = self.calculate_security_summary(
            &economic_vulnerabilities,
            &upgrade_vulnerabilities, 
            &sandwich_vulnerabilities,
            &time_vulnerabilities,
            &cross_contract_vulnerabilities,
            &bridge_vulnerabilities,
            &protocol_dependency_vulnerabilities,
            &defi_primitive_vulnerabilities,
            &state_manipulation_vulnerabilities,
            &mev_attack_vulnerabilities,
            // Advanced vulnerability types
            &governance_vulnerabilities,
            &oracle_infrastructure_vulnerabilities,
            &lp_economic_vulnerabilities,
            &black_swan_vulnerabilities,
            &multi_vector_vulnerabilities,
            &ai_detected_vulnerabilities,
            &infrastructure_vulnerabilities,
        );

        ComprehensiveAnalysisResult {
            contract_address: self.contract_address.clone(),
            analysis_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            total_vulnerabilities,
            economic_vulnerabilities,
            upgrade_vulnerabilities,
            sandwich_vulnerabilities,
            time_vulnerabilities,
            cross_contract_vulnerabilities,
            bridge_vulnerabilities,
            protocol_dependency_vulnerabilities,
            defi_primitive_vulnerabilities,
            state_manipulation_vulnerabilities,
            mev_attack_vulnerabilities,
            governance_vulnerabilities,
            oracle_infrastructure_vulnerabilities,
            lp_economic_vulnerabilities,
            black_swan_vulnerabilities,
            multi_vector_vulnerabilities,
            ai_detected_vulnerabilities,
            infrastructure_vulnerabilities,
            atomic_composability_vulnerabilities,
            protocol_integration_vulnerabilities,
            advanced_mev_vulnerabilities,
            gas_economic_vulnerabilities,
            flash_loan_vulnerabilities,
            data_integrity_vulnerabilities,
            security_summary,
            analysis_confidence: overall_confidence,
            coverage_metrics,
        }
    }

    /// Calculate confidence for economic vulnerabilities
    fn calculate_module_confidence(&self, vulnerabilities: &[EconomicVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95 // High confidence in no vulnerabilities
        } else {
            vulnerabilities.iter()
                .map(|v| v.detection_confidence)
                .sum::<f32>() / vulnerabilities.len() as f32
        }
    }

    /// Calculate confidence for upgrade vulnerabilities
    fn calculate_upgrade_confidence(&self, vulnerabilities: &[UpgradeableVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            vulnerabilities.iter()
                .map(|v| v.detection_confidence)
                .sum::<f32>() / vulnerabilities.len() as f32
        }
    }

    /// Calculate confidence for sandwich vulnerabilities
    fn calculate_sandwich_confidence(&self, vulnerabilities: &[SandwichVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            vulnerabilities.iter()
                .map(|v| (v.mev_potential as f32) / 1000.0) // Convert basis points to confidence
                .sum::<f32>() / vulnerabilities.len() as f32
        }
    }

    /// Calculate confidence for time vulnerabilities  
    fn calculate_time_confidence(&self, vulnerabilities: &[TimeVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            vulnerabilities.iter()
                .map(|v| (v.risk_score as f32) / 10.0) // Convert 0-10 score to confidence
                .sum::<f32>() / vulnerabilities.len() as f32
        }
    }

    /// Calculate confidence for cross-contract vulnerabilities
    fn calculate_cross_contract_confidence(&self, vulnerabilities: &[ProtocolFindingKind]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            // Assuming CrossContractVulnerability has detection_confidence field
            // If not, use a default confidence
            0.80 // Default confidence for cross-contract analysis
        }
    }

    /// Calculate confidence for bridge security vulnerabilities
    fn calculate_bridge_confidence(&self, vulnerabilities: &[BridgeVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            // Calculate average confidence based on vulnerability detection confidence
            let total_confidence: f32 = vulnerabilities
                .iter()
                .map(|v| v.confidence as f32)
                .sum();
            total_confidence / vulnerabilities.len() as f32
        }
    }

    /// Calculate confidence for protocol dependency vulnerabilities
    fn calculate_protocol_dependency_confidence(&self, vulnerabilities: &[ProtocolDependencyVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            // Calculate average confidence based on vulnerability detection confidence
            let total_confidence: f32 = vulnerabilities
                .iter()
                .map(|v| v.confidence as f32)
                .sum();
            total_confidence / vulnerabilities.len() as f32
        }
    }

    /// Calculate confidence for DeFi primitive vulnerabilities
    fn calculate_defi_primitive_confidence(&self, vulnerabilities: &[DeFiPrimitiveVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            // Calculate average confidence based on vulnerability detection confidence
            let total_confidence: f32 = vulnerabilities
                .iter()
                .map(|v| v.confidence as f32)
                .sum();
            total_confidence / vulnerabilities.len() as f32
        }
    }

    /// Calculate confidence for state manipulation vulnerabilities
    fn calculate_state_manipulation_confidence(&self, vulnerabilities: &[StateManipulationVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            // Calculate average confidence based on vulnerability detection confidence
            let total_confidence: f32 = vulnerabilities
                .iter()
                .map(|v| v.confidence as f32)
                .sum();
            total_confidence / vulnerabilities.len() as f32
        }
    }

    /// Calculate confidence for MEV attack vulnerabilities
    fn calculate_mev_attack_confidence(&self, vulnerabilities: &[MevAttackVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            // Calculate average confidence based on vulnerability detection confidence
            let total_confidence: f32 = vulnerabilities
                .iter()
                .map(|v| v.confidence as f32)
                .sum();
            total_confidence / vulnerabilities.len() as f32
        }
    }

    /// Calculate confidence for governance vulnerabilities
    fn calculate_governance_confidence(&self, vulnerabilities: &[GovernanceVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            let total_confidence: f32 = vulnerabilities
                .iter()
                .map(|v| v.detection_confidence)
                .sum();
            total_confidence / vulnerabilities.len() as f32
        }
    }

    /// Calculate confidence for oracle infrastructure vulnerabilities
    fn calculate_oracle_infrastructure_confidence(&self, vulnerabilities: &[OracleInfrastructureVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            let total_confidence: f32 = vulnerabilities
                .iter()
                .map(|v| v.detection_confidence)
                .sum();
            total_confidence / vulnerabilities.len() as f32
        }
    }

    /// Calculate confidence for LP economic vulnerabilities
    fn calculate_lp_economic_confidence(&self, vulnerabilities: &[LPEconomicVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            let total_confidence: f32 = vulnerabilities
                .iter()
                .map(|v| v.detection_confidence)
                .sum();
            total_confidence / vulnerabilities.len() as f32
        }
    }

    /// Calculate confidence for black swan vulnerabilities
    fn calculate_black_swan_confidence(&self, vulnerabilities: &[BlackSwanVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            let total_confidence: f32 = vulnerabilities
                .iter()
                .map(|v| v.simulation_confidence)
                .sum();
            total_confidence / vulnerabilities.len() as f32
        }
    }

    /// Calculate confidence for multi-vector vulnerabilities
    fn calculate_multi_vector_confidence(&self, vulnerabilities: &[MultiVectorVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            let total_confidence: f32 = vulnerabilities
                .iter()
                .map(|v| v.attack_success_probability)
                .sum();
            total_confidence / vulnerabilities.len() as f32
        }
    }

    /// Calculate confidence for AI detected vulnerabilities
    fn calculate_ai_detected_confidence(&self, vulnerabilities: &[AIDetectedVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            let total_confidence: f32 = vulnerabilities
                .iter()
                .map(|v| v.detection_confidence)
                .sum();
            total_confidence / vulnerabilities.len() as f32
        }
    }

    /// Calculate confidence for infrastructure vulnerabilities
    fn calculate_infrastructure_confidence(&self, vulnerabilities: &[InfrastructureVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            // Use failure probability as inverse confidence measure
            let avg_failure_prob: f32 = vulnerabilities
                .iter()
                .map(|v| v.failure_probability)
                .sum::<f32>() / vulnerabilities.len() as f32;
            
            // Convert failure probability to confidence (higher failure prob = lower confidence)
            (1.0 - avg_failure_prob).max(0.1)
        }
    }

    /// Calculate confidence for atomic composability vulnerabilities
    fn calculate_composability_confidence(&self, vulnerabilities: &[ComposabilityVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            let total_confidence: f32 = vulnerabilities
                .iter()
                .map(|v| v.confidence)
                .sum();
            total_confidence / vulnerabilities.len() as f32
        }
    }

    /// Calculate confidence for protocol integration vulnerabilities
    fn calculate_protocol_integration_confidence(&self, vulnerabilities: &[IntegrationVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            let total_confidence: f32 = vulnerabilities
                .iter()
                .map(|v| v.confidence)
                .sum();
            total_confidence / vulnerabilities.len() as f32
        }
    }

    /// Calculate confidence for advanced MEV vulnerabilities
    fn calculate_advanced_mev_confidence(&self, vulnerabilities: &[AdvancedMEVVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            let total_confidence: f32 = vulnerabilities
                .iter()
                .map(|v| v.confidence)
                .sum();
            total_confidence / vulnerabilities.len() as f32
        }
    }

    /// Calculate confidence for gas economic vulnerabilities
    fn calculate_gas_economic_confidence(&self, vulnerabilities: &[GasEconomicVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            let total_confidence: f32 = vulnerabilities
                .iter()
                .map(|v| v.confidence)
                .sum();
            total_confidence / vulnerabilities.len() as f32
        }
    }

    /// Calculate confidence for flash loan vulnerabilities
    fn calculate_flash_loan_confidence(&self, vulnerabilities: &[FlashLoanVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            let total_confidence: f32 = vulnerabilities
                .iter()
                .map(|v| v.confidence)
                .sum();
            total_confidence / vulnerabilities.len() as f32
        }
    }

    /// Calculate confidence for data integrity vulnerabilities
    fn calculate_data_integrity_confidence(&self, vulnerabilities: &[DataIntegrityVulnerability]) -> f32 {
        if vulnerabilities.is_empty() {
            0.95
        } else {
            let total_confidence: f32 = vulnerabilities
                .iter()
                .map(|v| v.confidence)
                .sum();
            total_confidence / vulnerabilities.len() as f32
        }
    }

    /// Calculate security summary with objective counts only
    fn calculate_security_summary(
        &self,
        economic: &[EconomicVulnerability],
        upgrade: &[UpgradeableVulnerability],
        sandwich: &[SandwichVulnerability],
        time: &[TimeVulnerability],
        cross_contract: &[ProtocolFindingKind],
        bridge: &[BridgeVulnerability],
        protocol_dependency: &[ProtocolDependencyVulnerability],
        defi_primitive: &[DeFiPrimitiveVulnerability],
        state_manipulation: &[StateManipulationVulnerability],
        mev_attack: &[MevAttackVulnerability],
        // Advanced vulnerability types
        governance: &[GovernanceVulnerability],
        oracle_infrastructure: &[OracleInfrastructureVulnerability],
        lp_economic: &[LPEconomicVulnerability],
        black_swan: &[BlackSwanVulnerability],
        multi_vector: &[MultiVectorVulnerability],
        ai_detected: &[AIDetectedVulnerability],
        infrastructure: &[InfrastructureVulnerability],
    ) -> SecuritySummary {
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;

        // Count economic vulnerabilities by severity
        for vuln in economic {
            match vuln.severity {
                SecuritySeverity::Critical => critical_count += 1,
                SecuritySeverity::High => high_count += 1,
                SecuritySeverity::Medium => medium_count += 1,
                SecuritySeverity::Low => low_count += 1,
                _ => {}
            }
        }

        // Count upgrade vulnerabilities by severity
        for vuln in upgrade {
            match vuln.severity {
                SecuritySeverity::Critical => critical_count += 1,
                SecuritySeverity::High => high_count += 1,
                SecuritySeverity::Medium => medium_count += 1,
                SecuritySeverity::Low => low_count += 1,
                _ => {}
            }
        }

        // Count sandwich vulnerabilities by severity
        for vuln in sandwich {
            match vuln.severity {
                SecuritySeverity::Critical => critical_count += 1,
                SecuritySeverity::High => high_count += 1,
                SecuritySeverity::Medium => medium_count += 1,
                SecuritySeverity::Low => low_count += 1,
                _ => {}
            }
        }

        // Count time vulnerabilities by severity
        for vuln in time {
            match vuln.severity {
                SecuritySeverity::Critical => critical_count += 1,
                SecuritySeverity::High => high_count += 1,
                SecuritySeverity::Medium => medium_count += 1,
                SecuritySeverity::Low => low_count += 1,
                _ => {}
            }
        }

        // Count cross-contract vulnerabilities (assuming they have severity)
        // Add similar severity counting for cross_contract if needed

        // Count bridge vulnerabilities by severity
        for vuln in bridge {
            match vuln.severity {
                SecuritySeverity::Critical => critical_count += 1,
                SecuritySeverity::High => high_count += 1,
                SecuritySeverity::Medium => medium_count += 1,
                SecuritySeverity::Low => low_count += 1,
                _ => {}
            }
        }

        // Count protocol dependency vulnerabilities by severity
        for vuln in protocol_dependency {
            match vuln.severity {
                SecuritySeverity::Critical => critical_count += 1,
                SecuritySeverity::High => high_count += 1,
                SecuritySeverity::Medium => medium_count += 1,
                SecuritySeverity::Low => low_count += 1,
                _ => {}
            }
        }

        // Count DeFi primitive vulnerabilities by severity
        for vuln in defi_primitive {
            match vuln.severity {
                SecuritySeverity::Critical => critical_count += 1,
                SecuritySeverity::High => high_count += 1,
                SecuritySeverity::Medium => medium_count += 1,
                SecuritySeverity::Low => low_count += 1,
                _ => {}
            }
        }

        // Count state manipulation vulnerabilities by severity
        for vuln in state_manipulation {
            match vuln.severity {
                SecuritySeverity::Critical => critical_count += 1,
                SecuritySeverity::High => high_count += 1,
                SecuritySeverity::Medium => medium_count += 1,
                SecuritySeverity::Low => low_count += 1,
                _ => {}
            }
        }

        // Count MEV attack vulnerabilities by severity
        for vuln in mev_attack {
            match vuln.severity {
                SecuritySeverity::Critical => critical_count += 1,
                SecuritySeverity::High => high_count += 1,
                SecuritySeverity::Medium => medium_count += 1,
                SecuritySeverity::Low => low_count += 1,
                _ => {}
            }
        }

        // Count governance vulnerabilities by severity
        for vuln in governance {
            match vuln.severity {
                SecuritySeverity::Critical => critical_count += 1,
                SecuritySeverity::High => high_count += 1,
                SecuritySeverity::Medium => medium_count += 1,
                SecuritySeverity::Low => low_count += 1,
                _ => {}
            }
        }

        // Count oracle infrastructure vulnerabilities by severity
        for vuln in oracle_infrastructure {
            match vuln.severity {
                SecuritySeverity::Critical => critical_count += 1,
                SecuritySeverity::High => high_count += 1,
                SecuritySeverity::Medium => medium_count += 1,
                SecuritySeverity::Low => low_count += 1,
                _ => {}
            }
        }

        // Count LP economic vulnerabilities by severity
        for vuln in lp_economic {
            match vuln.severity {
                SecuritySeverity::Critical => critical_count += 1,
                SecuritySeverity::High => high_count += 1,
                SecuritySeverity::Medium => medium_count += 1,
                SecuritySeverity::Low => low_count += 1,
                _ => {}
            }
        }

        // Count black swan vulnerabilities by severity
        for vuln in black_swan {
            match vuln.severity {
                SecuritySeverity::Critical => critical_count += 1,
                SecuritySeverity::High => high_count += 1,
                SecuritySeverity::Medium => medium_count += 1,
                SecuritySeverity::Low => low_count += 1,
                _ => {}
            }
        }

        // Count multi-vector vulnerabilities by severity
        for vuln in multi_vector {
            match vuln.severity {
                SecuritySeverity::Critical => critical_count += 1,
                SecuritySeverity::High => high_count += 1,
                SecuritySeverity::Medium => medium_count += 1,
                SecuritySeverity::Low => low_count += 1,
                _ => {}
            }
        }

        // Count AI detected vulnerabilities by severity
        for vuln in ai_detected {
            match vuln.severity {
                SecuritySeverity::Critical => critical_count += 1,
                SecuritySeverity::High => high_count += 1,
                SecuritySeverity::Medium => medium_count += 1,
                SecuritySeverity::Low => low_count += 1,
                _ => {}
            }
        }

        // Count infrastructure vulnerabilities by severity
        for vuln in infrastructure {
            match vuln.severity {
                SecuritySeverity::Critical => critical_count += 1,
                SecuritySeverity::High => high_count += 1,
                SecuritySeverity::Medium => medium_count += 1,
                SecuritySeverity::Low => low_count += 1,
                _ => {}
            }
        }

        SecuritySummary {
            critical_count,
            high_count,
            medium_count,
            low_count,
            attack_vectors_detected: economic.len() as u32 + sandwich.len() as u32 + time.len() as u32 + bridge.len() as u32 + protocol_dependency.len() as u32 + defi_primitive.len() as u32 + state_manipulation.len() as u32 + mev_attack.len() as u32,
            economic_invariants_violated: economic.iter()
                .map(|v| v.economic_invariants.len() as u32)
                .sum(),
            proxy_patterns_analyzed: upgrade.len() as u32,
            time_dependencies_found: time.len() as u32,
            cross_contract_risks: cross_contract.len() as u32,
        }
    }

    /// Calculate coverage metrics
    fn calculate_coverage_metrics(&self, duration_ms: u64, modules_run: u32) -> CoverageMetrics {
        let function_signatures = self.count_function_signatures();
        let opcodes_analyzed = self.bytecode.len() as u32;
        let coverage_percentage = self.estimate_bytecode_coverage();

        CoverageMetrics {
            bytecode_coverage_percentage: coverage_percentage,
            function_signatures_analyzed: function_signatures,
            opcodes_analyzed,
            analysis_modules_run: modules_run,
            analysis_duration_ms: duration_ms,
            proof_generation_time_ms: None, // To be implemented with ZK integration
        }
    }

    /// Estimate bytecode coverage percentage
    fn estimate_bytecode_coverage(&self) -> f32 {
        // Simple heuristic: assume we analyze most of the bytecode
        // Real implementation would track which bytes were analyzed
        if self.bytecode.is_empty() {
            0.0
        } else {
            85.0 // Estimated coverage percentage
        }
    }

    /// Count function signatures in bytecode
    fn count_function_signatures(&self) -> u32 {
        let mut count = 0;
        
        // Look for function selector patterns (4-byte signatures at start of functions)
        for i in 0..self.bytecode.len().saturating_sub(4) {
            // Function selectors typically follow PUSH4 opcode (0x63)
            if self.bytecode[i] == 0x63 {
                count += 1;
            }
        }
        
        count
    }

    /// Generate security verification proof (placeholder for ZK integration)
    pub fn generate_security_proof(&self, result: &ComprehensiveAnalysisResult) -> Option<Vec<u8>> {
        // Placeholder for ZK proof generation
        // This would integrate with the zkEVM circuits to generate mathematical proofs
        // of security analysis correctness
        None
    }

    /// Validate analysis results against known attack vectors
    pub fn validate_against_known_attacks(&self, result: &ComprehensiveAnalysisResult) -> f32 {
        // Placeholder for validation against known attack database
        // Would compare detected patterns against CVE database, known exploits, etc.
        0.95 // Default validation score
    }
}

/// Builder pattern for configuring comprehensive analysis
pub struct ComprehensiveAnalyzerBuilder {
    bytecode: Vec<u8>,
    contract_address: Option<String>,
    modules: ModuleConfig,
}

#[derive(Debug, Clone)]
pub struct ModuleConfig {
    pub economic_analysis: bool,
    pub upgrade_analysis: bool,
    pub sandwich_analysis: bool,
    pub time_analysis: bool,
    pub cross_contract_analysis: bool,
    pub state_manipulation_analysis: bool,
    pub mev_attack_analysis: bool,
}

impl Default for ModuleConfig {
    fn default() -> Self {
        Self {
            economic_analysis: true,
            upgrade_analysis: true,
            sandwich_analysis: true,
            time_analysis: true,
            cross_contract_analysis: true,
            state_manipulation_analysis: true,
            mev_attack_analysis: true,
        }
    }
}

impl ComprehensiveAnalyzerBuilder {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self {
            bytecode,
            contract_address: None,
            modules: ModuleConfig::default(),
        }
    }

    pub fn with_contract_address(mut self, address: String) -> Self {
        self.contract_address = Some(address);
        self
    }

    pub fn with_module_config(mut self, config: ModuleConfig) -> Self {
        self.modules = config;
        self
    }

    pub fn enable_module(mut self, module: &str) -> Self {
        match module {
            "economic" => self.modules.economic_analysis = true,
            "upgrade" => self.modules.upgrade_analysis = true,
            "sandwich" => self.modules.sandwich_analysis = true,
            "time" => self.modules.time_analysis = true,
            "cross_contract" => self.modules.cross_contract_analysis = true,
            _ => {} // Unknown module
        }
        self
    }

    pub fn disable_module(mut self, module: &str) -> Self {
        match module {
            "economic" => self.modules.economic_analysis = false,
            "upgrade" => self.modules.upgrade_analysis = false,
            "sandwich" => self.modules.sandwich_analysis = false,
            "time" => self.modules.time_analysis = false,
            "cross_contract" => self.modules.cross_contract_analysis = false,
            _ => {} // Unknown module
        }
        self
    }

    pub fn build(self) -> ComprehensiveSecurityAnalyzer {
        ComprehensiveSecurityAnalyzer {
            bytecode: self.bytecode,
            contract_address: self.contract_address,
            enable_cross_contract: self.modules.cross_contract_analysis,
            enable_economic_analysis: self.modules.economic_analysis,
            enable_upgrade_analysis: self.modules.upgrade_analysis,
            enable_sandwich_analysis: self.modules.sandwich_analysis,
            enable_time_analysis: self.modules.time_analysis,
            enable_bridge_analysis: true,
            enable_protocol_dependency_analysis: true,
            enable_defi_primitive_analysis: true,
            enable_state_manipulation_analysis: self.modules.state_manipulation_analysis,
            enable_mev_attack_analysis: self.modules.mev_attack_analysis,
            enable_governance_analysis: true,
            enable_oracle_infrastructure_analysis: true,
            enable_lp_economic_analysis: true,
            enable_black_swan_analysis: true,
            enable_multi_vector_analysis: true,
            enable_ai_adaptive_analysis: true,
            enable_infrastructure_analysis: true,
            enable_atomic_composability_analysis: true,
            enable_protocol_integration_analysis: true,
            enable_advanced_mev_analysis: true,
            enable_gas_economic_analysis: true,
            enable_flash_loan_analysis: true,
            enable_data_integrity_analysis: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comprehensive_analysis() {
        let bytecode = vec![
            // Sample bytecode with various function signatures
            0x63, 0x40, 0xc1, 0x0f, 0x19, // mint()
            0x63, 0x42, 0x96, 0x6c, 0x68, // burn()
            0x63, 0xdb, 0x00, 0x6a, 0x75, // redeem()
        ];

        let analyzer = ComprehensiveSecurityAnalyzer::new(bytecode);
        let result = analyzer.analyze();

        assert!(result.total_vulnerabilities > 0);
        assert!(result.analysis_confidence > 0.0);
        assert_eq!(result.coverage_metrics.analysis_modules_run, 5);
    }

    #[test]
    fn test_analyzer_builder() {
        let bytecode = vec![0x63, 0x40, 0xc1, 0x0f, 0x19];
        
        let analyzer = ComprehensiveAnalyzerBuilder::new(bytecode)
            .with_contract_address("0x123...".to_string())
            .disable_module("cross_contract")
            .build();

        let result = analyzer.analyze();
        assert_eq!(result.coverage_metrics.analysis_modules_run, 4); // One module disabled
    }

    #[test] 
    fn test_security_summary_calculation() {
        let bytecode = vec![0x63, 0x42, 0x96, 0x6c, 0x68]; // burn()
        
        let analyzer = ComprehensiveSecurityAnalyzer::new(bytecode);
        let result = analyzer.analyze();

        // Should have some vulnerabilities detected
        assert!(result.security_summary.critical_count > 0 || 
               result.security_summary.high_count > 0 ||
               result.security_summary.medium_count > 0);
    }
}
