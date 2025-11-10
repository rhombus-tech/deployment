use crate::errors::{VMError, Result};
use crate::security::{SecurityVerifier, VerificationResult, SecurityWarning, SecurityWarningKind, Severity, BytecodeLocation};
use crate::transaction::{Transaction, TransactionSequence};
use crate::types::VerificationLevel;
use std::sync::Arc;
#[allow(unused_imports)]
use async_trait::async_trait;

// Import the EVM Verify PCD components
use pcd::gateway::{DeploymentGateway, SecurityWarning as PCDSecurityWarning, GatewaySettings};
use pcd::circuit_impl::SecurityWarningKind as PCDSecurityWarningKind;
use pcd::Severity as PCDSeverity;
// Import the verification strategy types from the API
#[cfg(feature = "evm-verify")]
use evm_verify::api::VerificationStrategy;

#[cfg(not(feature = "evm-verify"))]
#[derive(Debug, Clone)]
pub enum VerificationStrategy {
    Groth16,
}

#[cfg(not(feature = "evm-verify"))]
#[derive(Debug, Clone)]
pub struct WARPVerificationContext;

/// PCD-based security verifier that uses the EVM Verify system
pub struct PCDSecurityVerifier {
    /// Gateway to the deployment proof verification system
    gateway: DeploymentGateway,
    /// Strategy for verification
    strategy: VerificationStrategy,
    /// Flag to use WARP for verification
    use_warp: bool,
    /// WARP verification context (only initialized when use_warp is true)
    #[cfg(feature = "warp-integration")]
    warp_context: Option<std::sync::Arc<warp_verification::WarpVerificationStrategy>>,
}

// SAFETY ANALYSIS for Send + Sync implementation:
//
// We must implement Send/Sync manually because DeploymentGateway contains
// Box<dyn VulnerabilityDetector> which doesn't implement Send/Sync by default.
//
// This is SAFE because:
// 1. DeploymentGateway's internal state is never mutated after construction
// 2. All detectors are stateless and read-only
// 3. The gateway only performs analysis, no mutable shared state
// 4. BytecodeAnalyzer is Send + Sync (verified)
// 5. VerificationStrategy is Copy
// 6. use_warp is Copy (bool)
//
// RISK: If pcd crate adds mutable state to DeploymentGateway in the future,
// this could become unsound. We rely on the pcd crate's API contract.
//
// TODO: Upstream fix to pcd crate to add Send + Sync to VulnerabilityDetector trait
unsafe impl Send for PCDSecurityVerifier {}
unsafe impl Sync for PCDSecurityVerifier {}

impl PCDSecurityVerifier {
    /// Create a new PCDSecurityVerifier with the given verification strategy
    pub fn new(strategy: VerificationStrategy, use_warp: bool) -> Self {
        let gateway_settings = GatewaySettings {
            allow_critical_warnings: false,
            min_severity: pcd::Severity::Info,
            generate_reports: true,
            analyze_action_sequences: true, // Enable PCD proving
        };
        let gateway = DeploymentGateway::new(gateway_settings);
        
        Self {
            gateway,
            strategy,
            use_warp,
        }
    }
    
    /// Create a new PCDSecurityVerifier with WARP verification and custom security parameters
    pub fn new_with_warp_params(security_param: usize) -> Self {
        let gateway_settings = GatewaySettings {
            allow_critical_warnings: false,
            min_severity: pcd::Severity::Info,
            generate_reports: true,
            analyze_action_sequences: true, // Enable PCD proving
        };
        let gateway = DeploymentGateway::new(gateway_settings);
        
        // WARP integration disabled for now due to missing dependencies
        
        Self {
            gateway,
            strategy: VerificationStrategy::Groth16,
            use_warp: false,
        }
    }
    
    /// Create a new PCD-based security verifier with the default Groth16 strategy
    pub fn new_with_default_strategy(gateway: Arc<DeploymentGateway>, _generate_proofs: bool) -> Self {
        Self {
            gateway: Arc::try_unwrap(gateway).unwrap_or_else(|_| panic!("Could not unwrap Arc for DeploymentGateway")),
            strategy: VerificationStrategy::Groth16,
            use_warp: false,
        }
    }
    
    /// Create a new PCD-based security verifier with the WARP strategy
    pub fn new_with_warp_strategy(gateway: Arc<DeploymentGateway>, _generate_proofs: bool) -> Self {
        Self {
            gateway: Arc::try_unwrap(gateway).unwrap_or_else(|_| panic!("Could not unwrap Arc for DeploymentGateway")),
            strategy: VerificationStrategy::Groth16,
            use_warp: true,
        }
    }
    
    /// Convert EVM Verify security warnings to our format
    fn convert_warnings(&self, pcd_warnings: Vec<PCDSecurityWarning>) -> Vec<SecurityWarning> {
        pcd_warnings.into_iter()
            .map(|warning| {
                // Map the PCD warning kind to our internal SecurityWarningKind
                // Only handle variants that exist in the PCD module
                let kind = match warning.kind {
                    PCDSecurityWarningKind::Reentrancy => SecurityWarningKind::Reentrancy,
                    PCDSecurityWarningKind::AccessControl => SecurityWarningKind::AccessControl,
                    PCDSecurityWarningKind::IntegerOverflow => SecurityWarningKind::IntegerOverflow,
                    PCDSecurityWarningKind::UncheckedCall => SecurityWarningKind::UncheckedCall,
                    PCDSecurityWarningKind::FrontRunning => SecurityWarningKind::FrontRunning,
                    PCDSecurityWarningKind::FlashLoan => SecurityWarningKind::FlashLoan,
                    PCDSecurityWarningKind::Other(ref s) => {
                        // Handle special cases based on the string content
                        if s.contains("MEV") || s.contains("mev") {
                            SecurityWarningKind::MEVVulnerability
                        } else if s.contains("price manipulation") || s.contains("Price Manipulation") {
                            SecurityWarningKind::PriceManipulation
                        } else if s.contains("oracle") || s.contains("Oracle") {
                            SecurityWarningKind::OracleManipulation
                        } else if s.contains("block number") || s.contains("Block Number") {
                            SecurityWarningKind::BlockNumberDependence
                        } else if s.contains("uninitialized") || s.contains("Uninitialized") {
                            SecurityWarningKind::UninitializedStorage
                        } else if s.contains("bitmask") || s.contains("BitMask") {
                            SecurityWarningKind::BitMaskVulnerability
                        } else if s.contains("governance") || s.contains("Governance") {
                            SecurityWarningKind::GovernanceVulnerability
                        } else if s.contains("cross-contract") || s.contains("Cross-Contract") || s.contains("reentrancy") {
                            SecurityWarningKind::CrossContractReentrancy
                        } else if s.contains("precision") || s.contains("Precision") {
                            SecurityWarningKind::PrecisionLoss
                        } else if s.contains("gas griefing") || s.contains("Gas Griefing") {
                            SecurityWarningKind::GasGriefing
                        } else if s.contains("upgradable") || s.contains("Upgradable") || s.contains("upgrade") {
                            SecurityWarningKind::Upgradability
                        } else if s.contains("underflow") || s.contains("Underflow") {
                            SecurityWarningKind::IntegerUnderflow
                        } else {
                            SecurityWarningKind::Other(s.clone())
                        }
                    }
                };
                
                // Map from PCD severity to our system's severity
                let severity = match warning.severity {
                    PCDSeverity::Critical => crate::security::Severity::Critical,
                    PCDSeverity::Warning => crate::security::Severity::Medium,
                    PCDSeverity::Info => crate::security::Severity::Low,
                };
                
                SecurityWarning {
                    code: "PCD-001".to_string(),
                    message: warning.description.clone(),
                    kind,
                    severity,
                    description: warning.description,
                    location: warning.location.map(|loc| crate::security::VulnerabilityLocation {
                        offset: loc.offset,
                        length: loc.length,
                        context: loc.context,
                    }),
                    remediation_hint: warning.remediation_hint.to_string(),
                }
            })
            .collect()
    }
}

#[async_trait]
impl SecurityVerifier for PCDSecurityVerifier {
    async fn verify_transaction(
        &self,
        transaction: &Transaction,
        level: VerificationLevel,
    ) -> Result<VerificationResult> {
        let verification_level = level.to_u32();
        let tx_bytes = serde_json::to_vec(transaction).map_err(|e| VMError::Serialization(e.to_string()))?;
        
        // Depending on whether WARP is enabled, use different verification paths
        if self.use_warp {
            // WARP verification disabled for now due to missing dependencies
            // Fall back to standard PCD verification
            let result = self.gateway.verify_contract_with_strategy(&tx_bytes, pcd::api::VerificationStrategy::Groth16)?;
            
            let security_warnings = self.convert_warnings(result.warnings);
            
            if result.passed {
                Ok(VerificationResult::success_with_warnings(security_warnings))
            } else {
                Ok(VerificationResult::failure_with_report(
                    "Transaction verification failed", 
                    result.report.map(|r| format!("{:?}", r)).unwrap_or_default()
                ))
            }
        } else {
            // Standard PCD verification path
            let result = self.gateway.verify_contract_with_strategy(&tx_bytes, pcd::api::VerificationStrategy::Groth16)?;
            
            // Convert the PCD security report to our format
            let security_warnings = self.convert_warnings(result.warnings);
                
            if result.passed {
                Ok(VerificationResult::success_with_warnings(security_warnings))
            } else {
                Ok(VerificationResult::failure_with_report("Deployment verification failed".to_string(), "Security verification did not pass".to_string()))
            }
        }
    }
    
    async fn verify_sequence(
        &self,
        sequence: &TransactionSequence,
        level: VerificationLevel,
    ) -> Result<VerificationResult> {
        let verification_level = level.to_u32();
        
        // Similar pattern to verify_transaction but for sequences
        if self.use_warp {
            // WARP verification temporarily disabled due to missing dependencies
            // Fallback to standard verification/ Prepare transaction data for batch verification
            let transactions = sequence.transactions();
            let mut tx_data_array = Vec::with_capacity(transactions.len());
            
            // Extract and serialize each transaction  
            for tx in transactions {
                let tx_bytes = serde_json::to_vec(&tx)
                    .map_err(|e| VMError::Serialization(format!("Failed to serialize transaction: {}", e)))?;
                tx_data_array.push(tx_bytes);
            }
            
            // Standard PCD verification path (WARP integration disabled for now)
            let result = self.gateway.verify_action_sequence(&tx_data_array)?;
            
            let security_warnings = self.convert_warnings(result.warnings);
                
            if result.passed {
                Ok(VerificationResult::success_with_warnings(security_warnings))
            } else {
                Ok(VerificationResult::failure_with_report(
                    "Sequence verification failed",
                    result.report.map(|r| format!("{:?}", r)).unwrap_or_default()
                ))
            }
            
            /* WARP integration disabled for now due to missing dependencies
            #[cfg(feature = "warp-integration")]
            match warp_integration::verify_with_warp(
                context,
                |context, data, level| async move {
                    // For sequence verification, we need to extract the individual transactions
                    // and verify them as a batch
                    let transactions = serde_json::from_slice::<Vec<Vec<u8>>>(data)
                        .map_err(|e| format!("Failed to parse transaction sequence: {}", e))?;
                    
                    // Convert to slice of slices for the verification API
                    let tx_refs: Vec<&[u8]> = transactions.iter().map(|tx| tx.as_slice()).collect();
                    
                    context.verify_transaction_sequence(&tx_refs, level).await
                },
                &serde_json::to_vec(&tx_data_array).map_err(|e| VMError::Serialization(format!("Failed to serialize transaction data: {}", e)))?,
                verification_level
            ).await {
                Ok(report) => {
                    // Convert the PCD security report to our format
                    let security_warnings = report.warnings.into_iter()
                        .map(|warning| self.convert_warnings(vec![warning]))
                        .collect();
                        
                    Ok(if report.passed {
                        VerificationResult::success_with_warnings(security_warnings)
                    } else {
                        VerificationResult::failure_with_report(
                            "WARP verification failed",
                            report.metrics.map(|m| m.to_string()).unwrap_or_default()
                        )
                    })
                },
                Err(err) => Err(VMError::ProofVerificationFailed { reason: format!("WARP sequence verification failed: {}", err) })
            }
            */
        } else {
            // Prepare transaction data for standard verification too
            let transactions = sequence.transactions();
            let mut tx_data_array = Vec::with_capacity(transactions.len());
            
            // Serialize each transaction for the verification gateway
            for tx in transactions {
                let tx_bytes = serde_json::to_vec(tx)
                    .map_err(|e| VMError::Serialization(format!("Failed to serialize transaction: {}", e)))?;
                tx_data_array.push(tx_bytes);
            }
            
            // Standard PCD verification path
            let result = self.gateway.verify_action_sequence(&tx_data_array)?;
            
            let security_warnings = self.convert_warnings(result.warnings);
                
            if result.passed {
                Ok(VerificationResult::success_with_warnings(security_warnings))
            } else {
                Ok(VerificationResult::failure_with_report("PCD verification failed".to_string(), "Security verification did not pass".to_string()))
            }
        }
    }    
}

/// Factory for creating PCD security verifiers
pub struct PCDVerifierFactory {
    strategy: VerificationStrategy,
    /// Flag to determine if WARP verification should be used
    use_warp: bool,
    /// WARP verification context (only initialized when use_warp is true)
    #[cfg(feature = "warp-integration")]
    warp_context: Option<std::sync::Arc<warp_verification::WarpVerificationStrategy>>,
}

impl Default for PCDVerifierFactory {
    /// Create a default PCD verifier factory with Groth16 strategy
    fn default() -> Self {
        Self {
            strategy: VerificationStrategy::Groth16,
            use_warp: false,
            #[cfg(feature = "warp-integration")]
            warp_context: None,
        }
    }
}

impl PCDVerifierFactory {
    /// Create a new PCD verifier factory with the specified strategy
    pub fn new(strategy: VerificationStrategy) -> Self {
        Self { 
            strategy,
            use_warp: false,
            #[cfg(feature = "warp-integration")]
            warp_context: None,
        }
    }

    /// Create a new PCD verifier factory with WARP verification
    pub fn with_use_warp(mut self, use_warp: bool) -> Self {
        // Update the use_warp flag
        self.use_warp = use_warp;
        
        // WARP integration disabled for now due to missing dependencies
        // No context initialization needed
        
        #[cfg(feature = "warp-integration")]
        {
            if use_warp && self.warp_context.is_none() {
                self.warp_context = Some(warp_integration::create_warp_context());
            } else if !use_warp {
                self.warp_context = None;
            }
        }
        
        self
    }

    /// Create a new PCD security verifier
    pub fn create(
        &self,
        _config_path: Option<&str>,
        generate_proofs: bool,
    ) -> Result<Arc<dyn SecurityVerifier>> {
        // Check if we're creating a WARP verifier
        if self.use_warp {
            // Create a deployment gateway with the appropriate settings
        let gateway_settings = pcd::gateway::GatewaySettings {
            allow_critical_warnings: false,
            min_severity: pcd::Severity::Info,
            generate_reports: true,
            analyze_action_sequences: true, // Enable PCD proving
        };
        let gateway = Arc::new(DeploymentGateway::new(gateway_settings));  
            let verifier = PCDSecurityVerifier::new_with_warp_strategy(gateway, generate_proofs);
            return Ok(Arc::new(verifier));
        }
        // Create a gateway with action sequence analysis enabled
        let gateway_settings = pcd::gateway::GatewaySettings {
            allow_critical_warnings: false,
            min_severity: pcd::Severity::Info,
            generate_reports: true,
            analyze_action_sequences: true, // Enable PCD proving
        };
        let gateway = pcd::gateway::create_default_gateway(Some(gateway_settings))?;
        
        // Create our PCD verifier with the specified strategy
        let verifier = PCDSecurityVerifier::new(
            self.strategy.clone(),
            generate_proofs,
        );
        
        Ok(Arc::new(verifier))
    }
    
    /// Create a new PCD security verifier with a specific strategy
    pub fn create_with_strategy(
        strategy: VerificationStrategy,
        _config_path: Option<&str>,
        generate_proofs: bool,
    ) -> Result<Arc<dyn SecurityVerifier>> {
        // Create a gateway with action sequence analysis enabled
        let gateway_settings = pcd::gateway::GatewaySettings {
            allow_critical_warnings: false,
            min_severity: pcd::Severity::Info,
            generate_reports: true,
            analyze_action_sequences: true, // Enable PCD proving
        };
        let gateway = pcd::gateway::create_default_gateway(Some(gateway_settings))?;
        
        // Create our PCD verifier with the specified strategy
        let verifier = PCDSecurityVerifier::new(
            strategy,
            generate_proofs,
        );
        
        Ok(Arc::new(verifier))
    }
}
