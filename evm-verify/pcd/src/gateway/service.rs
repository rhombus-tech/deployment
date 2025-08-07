use anyhow::{Result, anyhow};
use crate::bytecode_analyzer::{BytecodeAnalyzer, SecurityWarningKind as AnalyzerWarningKind};
use crate::circuit_impl::SecurityWarningKind as CircuitWarningKind;
use ethers::types::Bytes;
use super::detector::{VulnerabilityDetector, SecurityWarning, Severity, remediation_hint_for_vulnerability};
use super::report::{SecurityReport, SecurityReportGenerator};
// Import the verification strategy types from the API
use crate::api::VerificationStrategy;

/// Settings for the deployment gateway behavior
#[derive(Debug, Clone)]
pub struct GatewaySettings {
    /// Whether to allow critical warnings (default: false)
    pub allow_critical_warnings: bool,
    /// Minimum severity level to report (default: Info)
    pub min_severity: Severity,
    /// Whether to generate detailed reports (default: true)
    pub generate_reports: bool,
    /// Whether to analyze agent action sequences (default: false)
    pub analyze_action_sequences: bool,
}

impl Default for GatewaySettings {
    fn default() -> Self {
        Self {
            allow_critical_warnings: false,
            min_severity: Severity::Info,
            generate_reports: true,
            analyze_action_sequences: false,
        }
    }
}

/// Result of a verification operation
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether verification passed based on gateway settings
    pub passed: bool,
    /// List of security warnings found
    pub warnings: Vec<SecurityWarning>,
    /// Detailed security report if generate_reports is enabled
    pub report: Option<SecurityReport>,
}

/// Core gateway service for verifying AI-generated smart contracts and agent actions
pub struct DeploymentGateway {
    /// Bytecode analyzer for static analysis (initialized during verification)
    analyzer: Option<BytecodeAnalyzer>,
    /// Security detectors registered with the gateway
    detectors: Vec<Box<dyn VulnerabilityDetector>>,
    /// Gateway configuration
    pub settings: GatewaySettings,
    /// Security report generator
    pub report_generator: SecurityReportGenerator,
    /// Default verification strategy
    pub default_strategy: VerificationStrategy,
}

impl DeploymentGateway {
    /// Create a new deployment gateway instance with default verification strategy (Groth16)
    pub fn new(settings: GatewaySettings) -> Self {
        Self {
            analyzer: None,
            detectors: Vec::new(),
            settings,
            report_generator: SecurityReportGenerator::new(),
            default_strategy: VerificationStrategy::Groth16,
        }
    }
    
    /// Create a new deployment gateway instance with a specific verification strategy
    pub fn new_with_strategy(settings: GatewaySettings, strategy: VerificationStrategy) -> Self {
        Self {
            analyzer: None,
            detectors: Vec::new(),
            settings,
            report_generator: SecurityReportGenerator::new(),
            default_strategy: strategy,
        }
    }

    /// Register a new vulnerability detector with the gateway
    pub fn register_detector(&mut self, detector: Box<dyn VulnerabilityDetector>) -> &mut Self {
        self.detectors.push(detector);
        self
    }

    /// Set test mode on the bytecode analyzer (useful for testing)
    /// Note: This is a placeholder for future implementation
    pub fn set_test_mode(&mut self, _test_mode: bool) -> &mut Self {
        // No implementation since we create the analyzer during verification
        self
    }

    /// Verify contract bytecode for security vulnerabilities using the default strategy
    pub fn verify_contract(&self, bytecode: &[u8]) -> Result<VerificationResult> {
        self.verify_contract_with_strategy(bytecode, self.default_strategy.clone())
    }
    
    /// Verify contract bytecode for security vulnerabilities with a specific verification strategy
    pub fn verify_contract_with_strategy(&self, bytecode: &[u8], strategy: VerificationStrategy) -> Result<VerificationResult> {
        // Run all registered detectors on the bytecode
        let mut all_warnings = Vec::new();
        // We no longer need to initialize analyzer here since each detector creates its own
        
        for detector in &self.detectors {
            match detector.detect_with_strategy(bytecode, strategy.clone()) {
                Ok(warnings) => {
                    // Filter warnings by minimum severity
                    let filtered_warnings = warnings.into_iter()
                        .filter(|w| w.severity >= self.settings.min_severity)
                        .collect::<Vec<_>>();
                    
                    all_warnings.extend(filtered_warnings);
                }
                Err(e) => {
                    // Log error but continue with other detectors
                    eprintln!("Error in detector {}: {}", detector.name(), e);
                }
            }
        }
        
        // Generate security report if enabled
        let report = if self.settings.generate_reports {
            Some(self.report_generator.generate(bytecode, &all_warnings))
        } else {
            None
        };
        
        // Determine if verification passed based on settings
        let critical_warnings = all_warnings.iter()
            .filter(|w| w.severity == Severity::Critical)
            .count();
        
        let passed = critical_warnings == 0 || self.settings.allow_critical_warnings;
        
        Ok(VerificationResult {
            passed,
            warnings: all_warnings,
            report,
        })
    }
    
    /// Verify an AI agent action sequence for security vulnerabilities using the default strategy
    /// This analyzes a sequence of actions as a single unit
    pub fn verify_action_sequence(&self, actions: &[Vec<u8>]) -> Result<VerificationResult> {
        self.verify_action_sequence_with_strategy(actions, self.default_strategy.clone())
    }
    
    /// Verify an AI agent action sequence for security vulnerabilities with a specific verification strategy
    /// This analyzes a sequence of actions as a single unit
    pub fn verify_action_sequence_with_strategy(&self, actions: &[Vec<u8>], _strategy: VerificationStrategy) -> Result<VerificationResult> {
        if !self.settings.analyze_action_sequences {
            return Err(anyhow!("Action sequence analysis is disabled in settings"));
        }
        
        // For now, we analyze each action individually and combine results
        // In a more advanced implementation, we would analyze the sequence as a whole
        let mut all_warnings = Vec::new();
        
        for (i, action) in actions.iter().enumerate() {
            let result = self.verify_contract(action)?;
            
            // Add context to warnings
            let action_warnings = result.warnings.into_iter().map(|mut w| {
                let new_description = format!("Action {}: {}", i + 1, w.description);
                w.description = new_description;
                w
            }).collect::<Vec<_>>();
            
            all_warnings.extend(action_warnings);
        }
        
        // Add sequence-specific warnings
        if actions.len() > 1 {
            // Check for potential issues in multi-step sequences
            self.analyze_sequence_specific_issues(actions, &mut all_warnings);
        }
        
        // Generate security report if enabled
        let report = if self.settings.generate_reports {
            Some(self.report_generator.generate_sequence_report(actions, &all_warnings))
        } else {
            None
        };
        
        // Determine if verification passed based on settings
        let critical_warnings = all_warnings.iter()
            .filter(|w| w.severity == Severity::Critical)
            .count();
        
        let passed = critical_warnings == 0 || self.settings.allow_critical_warnings;
        
        Ok(VerificationResult {
            passed,
            warnings: all_warnings,
            report,
        })
    }
    
    /// Check for issues specific to action sequences
    fn analyze_sequence_specific_issues(&self, _actions: &[Vec<u8>], _warnings: &mut Vec<SecurityWarning>) {
        // Placeholder for sequence-specific issues
        // In a real implementation, this would look for patterns across multiple actions
        // and identify potential issues like inconsistent state handling
    }
}

/// Create a default gateway with standard detectors using Groth16 strategy
pub fn create_default_gateway(settings: Option<GatewaySettings>) -> Result<DeploymentGateway> {
    create_gateway_with_strategy(settings, VerificationStrategy::Groth16)
}

/// Create a gateway with standard detectors and a specific verification strategy
pub fn create_gateway_with_strategy(
    settings: Option<GatewaySettings>,
    strategy: VerificationStrategy
) -> Result<DeploymentGateway> {
    let settings = settings.unwrap_or_default();
    
    let mut gateway = DeploymentGateway::new_with_strategy(settings, strategy);
    
    // Register standard detectors
    gateway
        .register_detector(Box::new(ReentrancyDetector::new()))
        .register_detector(Box::new(PrecisionLossDetector::new()))
        .register_detector(Box::new(CrossContractReentrancyDetector::new()))
        .register_detector(Box::new(GasGriefingDetector::new()))
        .register_detector(Box::new(UninitializedStorageDetector::new()))
        .register_detector(Box::new(MEVVulnerabilityDetector::new()));
    
    Ok(gateway)
}

// Implementation of individual detectors
// These leverage your existing vulnerability detection implementations

/// Detector for reentrancy vulnerabilities
pub struct ReentrancyDetector;

impl ReentrancyDetector {
    pub fn new() -> Self {
        Self {}
    }
}

impl VulnerabilityDetector for ReentrancyDetector {
    fn detect_with_strategy(&self, bytecode: &[u8], strategy: VerificationStrategy) -> Result<Vec<SecurityWarning>> {
        // Use BytecodeAnalyzer to check for reentrancy patterns with the specified strategy
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode.to_vec()));
        
        // Configure the analyzer based on the verification strategy
        if let VerificationStrategy::ZODA = strategy {
            // Configure analyzer for ZODA strategy if needed
            println!("Using ZODA strategy for reentrancy detection");
        }
        
        let _analysis_result = analyzer.analyze()?;
        
        // Check if any reentrancy warnings were found
        let reentrancy_warnings = _analysis_result.security_warnings.iter()
            .filter(|w| matches!(w.kind, AnalyzerWarningKind::Reentrancy))
            .count() > 0;
            
        if reentrancy_warnings {
            Ok(vec![SecurityWarning {
                kind: CircuitWarningKind::Reentrancy,
                severity: Severity::Critical,
                description: "Detected potential reentrancy vulnerability".to_string(),
                location: None,
                remediation_hint: remediation_hint_for_vulnerability(&CircuitWarningKind::Reentrancy),
            }])
        } else {
            Ok(Vec::new())
        }
    }
    
    fn name(&self) -> &'static str {
        "Reentrancy Detector"
    }
    
    fn description(&self) -> &'static str {
        "Detects reentrancy vulnerabilities where a contract can be re-entered before state updates are applied"
    }
}

/// Detector for precision loss vulnerabilities
pub struct PrecisionLossDetector;

impl PrecisionLossDetector {
    pub fn new() -> Self {
        Self {}
    }
}

impl VulnerabilityDetector for PrecisionLossDetector {
    fn detect_with_strategy(&self, bytecode: &[u8], strategy: VerificationStrategy) -> Result<Vec<SecurityWarning>> {
        // Use BytecodeAnalyzer to check for precision loss patterns with the specified strategy
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode.to_vec()));
        
        // Configure the analyzer based on the verification strategy
        if let VerificationStrategy::ZODA = strategy {
            // Configure analyzer for ZODA strategy if needed
            println!("Using ZODA strategy for precision loss detection");
        }
        
        let _analysis_result = analyzer.analyze()?;
        
        // Check if any integer overflow warnings were found
        let overflow_warnings = _analysis_result.security_warnings.iter()
            .filter(|w| matches!(w.kind, AnalyzerWarningKind::IntegerOverflow))
            .count() > 0;
            
        if overflow_warnings {
            Ok(vec![SecurityWarning {
                kind: CircuitWarningKind::IntegerOverflow,
                severity: Severity::Warning,
                description: "Detected potential precision loss in calculations".to_string(),
                location: None,
                remediation_hint: remediation_hint_for_vulnerability(&CircuitWarningKind::IntegerOverflow),
            }])
        } else {
            Ok(Vec::new())
        }
    }
    
    fn name(&self) -> &'static str {
        "Precision Loss Detector"
    }
    
    fn description(&self) -> &'static str {
        "Detects scenarios where numerical precision may be lost, such as division before multiplication"
    }
}

/// Detector for cross-contract reentrancy vulnerabilities
pub struct CrossContractReentrancyDetector;

impl CrossContractReentrancyDetector {
    pub fn new() -> Self {
        Self {}
    }
}

impl VulnerabilityDetector for CrossContractReentrancyDetector {
    fn detect_with_strategy(&self, bytecode: &[u8], strategy: VerificationStrategy) -> Result<Vec<SecurityWarning>> {
        // Use BytecodeAnalyzer to check for cross-contract reentrancy patterns with the specified strategy
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode.to_vec()));
        
        // Configure the analyzer based on the verification strategy
        if let VerificationStrategy::ZODA = strategy {
            // Configure analyzer for ZODA strategy if needed
            println!("Using ZODA strategy for cross-contract reentrancy detection");
        }
        
        let _analysis_result = analyzer.analyze()?;
        
        // Check if any reentrancy warnings were found
        let reentrancy_warnings = _analysis_result.security_warnings.iter()
            .filter(|w| matches!(w.kind, AnalyzerWarningKind::Reentrancy))
            .count() > 0;
            
        if reentrancy_warnings && self.name().contains("CrossContract") {
            let kind_val = CircuitWarningKind::Other("CrossContractReentrancy".to_string());
            Ok(vec![SecurityWarning {
                kind: kind_val.clone(),
                severity: Severity::Critical,
                description: "Detected potential cross-contract reentrancy vulnerability".to_string(),
                location: None,
                remediation_hint: remediation_hint_for_vulnerability(&kind_val),
            }])
        } else {
            Ok(Vec::new())
        }
    }
    
    fn name(&self) -> &'static str {
        "Cross-Contract Reentrancy Detector"
    }
    
    fn description(&self) -> &'static str {
        "Detects reentrancy vulnerabilities across multiple contract interactions"
    }
}

/// Detector for gas griefing vulnerabilities
pub struct GasGriefingDetector;

impl GasGriefingDetector {
    pub fn new() -> Self {
        Self {}
    }
}

impl VulnerabilityDetector for GasGriefingDetector {
    fn detect_with_strategy(&self, bytecode: &[u8], strategy: VerificationStrategy) -> Result<Vec<SecurityWarning>> {
        // Use BytecodeAnalyzer to check for gas griefing patterns with the specified strategy
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode.to_vec()));
        
        // Configure the analyzer based on the verification strategy
        if let VerificationStrategy::ZODA = strategy {
            // Configure analyzer for ZODA strategy if needed
            println!("Using ZODA strategy for gas griefing detection");
        }
        
        let _analysis_result = analyzer.analyze()?;
        
        // Check if any unchecked call warnings were found
        let unchecked_calls = _analysis_result.security_warnings.iter()
            .filter(|w| matches!(w.kind, AnalyzerWarningKind::UncheckedCall))
            .count() > 0;
            
        if unchecked_calls {
            let kind_val = CircuitWarningKind::Other("GasGriefing".to_string());
            Ok(vec![SecurityWarning {
                kind: kind_val.clone(),
                severity: Severity::Critical,
                description: "Detected potential gas griefing vulnerability".to_string(),
                location: None,
                remediation_hint: remediation_hint_for_vulnerability(&kind_val),
            }])
        } else {
            Ok(Vec::new())
        }
    }
    
    fn name(&self) -> &'static str {
        "Gas Griefing Detector"
    }
    
    fn description(&self) -> &'static str {
        "Detects gas griefing vulnerabilities where a contract can be forced to consume excessive gas"
    }
}

/// Detector for uninitialized storage vulnerabilities
pub struct UninitializedStorageDetector;

impl UninitializedStorageDetector {
    pub fn new() -> Self {
        Self {}
    }
}

impl VulnerabilityDetector for UninitializedStorageDetector {
    fn detect_with_strategy(&self, bytecode: &[u8], strategy: VerificationStrategy) -> Result<Vec<SecurityWarning>> {
        // Use BytecodeAnalyzer to check for uninitialized storage patterns with the specified strategy
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode.to_vec()));
        
        // Configure the analyzer based on the verification strategy
        if let VerificationStrategy::ZODA = strategy {
            // Configure analyzer for ZODA strategy if needed
            println!("Using ZODA strategy for uninitialized storage detection");
        }
        
        let _analysis_result = analyzer.analyze()?;
        
        // Generate a warning for uninitialized storage if any SLOAD opcodes found without matching SSTORE
        // In real implementation, would use actual detection
        if bytecode.windows(2).any(|w| w == [0x54, 0x50]) { // SLOAD followed by POP
            let kind_val = CircuitWarningKind::Other("UninitializedStorage".to_string());
            Ok(vec![SecurityWarning {
                kind: kind_val.clone(),
                severity: Severity::Warning,
                description: "Detected potential uninitialized storage access".to_string(),
                location: None,
                remediation_hint: remediation_hint_for_vulnerability(&kind_val),
            }])
        } else {
            Ok(Vec::new())
        }
    }
    
    fn name(&self) -> &'static str {
        "Uninitialized Storage Detector"
    }
    
    fn description(&self) -> &'static str {
        "Detects reading from storage variables before they are initialized"
    }
}

/// Detector for MEV vulnerabilities
pub struct MEVVulnerabilityDetector;

impl MEVVulnerabilityDetector {
    pub fn new() -> Self {
        Self {}
    }
}

impl VulnerabilityDetector for MEVVulnerabilityDetector {
    fn detect_with_strategy(&self, bytecode: &[u8], strategy: VerificationStrategy) -> Result<Vec<SecurityWarning>> {
        // Use BytecodeAnalyzer to check for MEV vulnerability patterns with the specified strategy
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode.to_vec()));
        
        // Configure the analyzer based on the verification strategy
        if let VerificationStrategy::ZODA = strategy {
            // Configure analyzer for ZODA strategy if needed
            println!("Using ZODA strategy for MEV vulnerability detection");
        }
        
        let _analysis_result = analyzer.analyze()?;
        
        // Check if any price manipulation warnings were found
        let price_warnings = _analysis_result.security_warnings.iter()
            .filter(|w| matches!(w.kind, AnalyzerWarningKind::PriceManipulation))
            .count() > 0;
            
        if price_warnings {
            let kind_val = CircuitWarningKind::FrontRunning;
            Ok(vec![SecurityWarning {
                kind: kind_val.clone(),
                severity: Severity::Warning,
                description: "Detected potential MEV vulnerability".to_string(),
                location: None,
                remediation_hint: remediation_hint_for_vulnerability(&kind_val),
            }])
        } else {
            Ok(Vec::new())
        }
    }
    
    fn name(&self) -> &'static str {
        "MEV Vulnerability Detector"
    }
    
    fn description(&self) -> &'static str {
        "Detects vulnerabilities related to Maximal Extractable Value (MEV), such as front-running opportunities"
    }
}

/// Detector for oracle manipulation vulnerabilities
pub struct OracleManipulationDetector;

impl OracleManipulationDetector {
    pub fn new() -> Self {
        Self {}
    }
}

impl VulnerabilityDetector for OracleManipulationDetector {
    fn detect_with_strategy(&self, bytecode: &[u8], strategy: VerificationStrategy) -> Result<Vec<SecurityWarning>> {
        // Use BytecodeAnalyzer to check for oracle manipulation patterns with the specified strategy
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode.to_vec()));
        
        // Configure the analyzer based on the verification strategy
        if let VerificationStrategy::ZODA = strategy {
            // Configure analyzer for ZODA strategy if needed
            println!("Using ZODA strategy for oracle manipulation detection");
        }
        
        let _analysis_result = analyzer.analyze()?;
        
        // Check if any oracle manipulation warnings might be found
        // This is a simplistic check - in a real implementation, would use actual detection
        if bytecode.len() > 100 && bytecode.windows(2).any(|w| w == [0x73, 0xff]) { // PUSH20 0xff... (common oracle address pattern)
            let kind_val = CircuitWarningKind::Other("OracleManipulation".to_string());
            Ok(vec![SecurityWarning {
                kind: kind_val.clone(),
                severity: Severity::Warning,
                description: "Detected potential oracle manipulation vulnerability".to_string(),
                location: None,
                remediation_hint: remediation_hint_for_vulnerability(&kind_val),
            }])
        } else {
            Ok(Vec::new())
        }
    }
    
    fn name(&self) -> &'static str {
        "Oracle Manipulation Detector"
    }
    
    fn description(&self) -> &'static str {
        "Detects vulnerabilities related to oracle manipulation and price feeds"
    }
}
