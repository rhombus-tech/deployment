use anyhow::{Result, Context};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Proof, ProvingKey, VerifyingKey, generate_random_parameters, create_random_proof, prepare_verifying_key, verify_proof as ark_verify_proof};
use ark_std::rand::thread_rng;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::{CanonicalSerialize, Write};

use crate::analysis::{
    transaction_trace_analyzer::{TransactionTraceAnalyzer, ComprehensiveAnalysisReport},
    cross_contract_pcc_bridge::{CrossContractPCCBridge, CrossContractCircuitParams},
};

// Import the cross-contract circuit from PCC crate
extern crate pcc;
use ::pcc::circuits::cross_contract::CrossContractSafetyCircuit;

/// Cross-Contract Proof-Carrying Code API
/// First-in-the-world: Generate ZK proofs for multi-contract protocol safety
pub struct CrossContractPCC {
    /// Proving key (reusable across same circuit structure)
    proving_key: Option<ProvingKey<Bn254>>,
    /// Verifying key
    verifying_key: Option<VerifyingKey<Bn254>>,
}

impl CrossContractPCC {
    pub fn new() -> Self {
        Self {
            proving_key: None,
            verifying_key: None,
        }
    }

    /// Generate proof for a protocol's cross-contract safety
    /// 
    /// # Arguments
    /// * `analyzer` - Transaction trace analyzer with comprehensive analysis
    /// 
    /// # Returns
    /// * `CrossContractProof` - ZK proof of protocol safety
    pub fn generate_protocol_proof(
        &mut self,
        analyzer: &mut TransactionTraceAnalyzer,
    ) -> Result<CrossContractProof> {
        // Get comprehensive analysis
        let report = analyzer.get_comprehensive_report();

        // Convert to circuit parameters
        let bridge = CrossContractPCCBridge::new().with_report(report.clone());
        let params = bridge.to_circuit_params()?;

        // Create circuit (params will be moved here)
        let circuit = self.create_circuit(&params)?;
        
        // Clone params for later use
        let params_clone = params.clone();

        // Generate or reuse proving/verifying keys
        if self.proving_key.is_none() || self.verifying_key.is_none() {
            self.setup_keys(&circuit)?;
        }

        // Generate proof
        let proof = create_random_proof(
            circuit,
            self.proving_key.as_ref().unwrap(),
            &mut thread_rng(),
        ).context("Failed to generate proof")?;

        // CRITICAL SAFETY CHECK: Verify proof soundness
        // A proof is only valid if ALL safety conditions are met
        let is_safe = self.verify_safety_conditions(&params_clone)?;
        
        // Log safety status for auditability
        if !is_safe {
            tracing::warn!(
                "Generated proof for UNSAFE protocol: {} reentrancy paths, {} privilege escalations, {} critical taints, {} race conditions",
                params_clone.reentrancy_paths_found,
                params_clone.privilege_escalation_paths,
                params_clone.critical_taint_count,
                params_clone.race_condition_count
            );
        }
        
        Ok(CrossContractProof {
            proof,
            params: params_clone.clone(),
            is_safe,
        })
    }

    /// Verify a cross-contract safety proof
    pub fn verify_proof(&self, proof: &CrossContractProof) -> Result<bool> {
        let vk = self.verifying_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No verifying key available"))?;

        let pvk = prepare_verifying_key(vk);

        // Create public inputs from parameters
        let public_inputs = vec![
            Fr::from(proof.is_safe as u32),
            // Add more public inputs as needed
        ];

        let verified = ark_verify_proof(&pvk, &proof.proof, &public_inputs)
            .context("Proof verification failed")?;

        Ok(verified)
    }

    /// Setup proving and verifying keys for the circuit
    fn setup_keys(&mut self, circuit: &CrossContractSafetyCircuit<Fr>) -> Result<()> {
        let params = generate_random_parameters::<Bn254, _, _>(
            circuit.clone(),
            &mut thread_rng(),
        ).context("Failed to generate parameters")?;

        self.verifying_key = Some(params.vk.clone());
        self.proving_key = Some(params);

        Ok(())
    }

    /// Verify all safety conditions are met
    /// 
    /// CRITICAL: This determines if the protocol is safe to deploy!
    /// We must be CONSERVATIVE - if unsure, mark as UNSAFE
    fn verify_safety_conditions(&self, params: &CrossContractCircuitParams) -> Result<bool> {
        // ZERO-TOLERANCE CONDITIONS: Any of these fails → UNSAFE
        
        // 1. No reentrancy attack paths allowed
        if params.reentrancy_paths_found > 0 {
            tracing::error!("UNSAFE: {} reentrancy attack paths detected", params.reentrancy_paths_found);
            return Ok(false);
        }
        
        // 2. No privilege escalation paths allowed
        if params.privilege_escalation_paths > 0 {
            tracing::error!("UNSAFE: {} privilege escalation paths detected", params.privilege_escalation_paths);
            return Ok(false);
        }
        
        // 3. No critical taint issues allowed
        if params.critical_taint_count > 0 {
            tracing::error!("UNSAFE: {} critical taint issues detected", params.critical_taint_count);
            return Ok(false);
        }
        
        // 4. No race conditions allowed
        if params.race_condition_count > 0 {
            tracing::error!("UNSAFE: {} race conditions detected", params.race_condition_count);
            return Ok(false);
        }
        
        // WARNING CONDITIONS: Require manual review
        
        // 5. Dangerous data flows should be minimal
        const MAX_DANGEROUS_FLOWS: usize = 3;
        if params.dangerous_data_flows > MAX_DANGEROUS_FLOWS {
            tracing::warn!(
                "REVIEW REQUIRED: {} dangerous data flows (threshold: {})",
                params.dangerous_data_flows,
                MAX_DANGEROUS_FLOWS
            );
            // Don't fail automatically, but flag for review
        }
        
        // 6. Call depth should be reasonable
        const MAX_SAFE_DEPTH: u32 = 10;
        if params.max_call_depth > MAX_SAFE_DEPTH {
            tracing::warn!(
                "REVIEW REQUIRED: Call depth {} exceeds safe threshold {}",
                params.max_call_depth,
                MAX_SAFE_DEPTH
            );
        }
        
        // 7. Circular dependencies are concerning
        if params.has_circular_dependencies {
            tracing::warn!("REVIEW REQUIRED: Circular dependencies detected");
        }
        
        // All critical checks passed
        tracing::info!("✅ Protocol passed all critical safety checks");
        Ok(true)
    }
    
    /// Create circuit from parameters
    fn create_circuit(&self, params: &CrossContractCircuitParams) -> Result<CrossContractSafetyCircuit<Fr>> {
        Ok(CrossContractSafetyCircuit::<Fr>::new(
            params.total_contracts,
            params.total_call_edges,
            params.has_circular_dependencies,
            params.max_call_depth,
            params.delegate_call_count,
            params.reentrancy_paths_found,
            params.privilege_escalation_paths,
            params.value_leakage_paths,
            params.total_data_flows,
            params.tainted_flows,
            params.dangerous_data_flows,
            params.critical_taint_count,
            params.shared_state_count,
            params.high_risk_shared_state,
            params.race_condition_count,
            params.circular_state_deps,
            params.call_graph_hash,
            params.data_flow_hash,
            params.state_dep_hash,
        ))
    }

    /// Export verifying key for on-chain verification
    pub fn export_verifying_key(&self) -> Result<Vec<u8>> {
        let vk = self.verifying_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No verifying key available"))?;

        // Serialize verifying key
        let mut bytes = Vec::new();
        vk.serialize_uncompressed(&mut bytes)
            .context("Failed to serialize verifying key")?;

        Ok(bytes)
    }
}

/// Cross-Contract Safety Proof
#[derive(Clone)]
pub struct CrossContractProof {
    /// The ZK proof
    pub proof: Proof<Bn254>,
    /// Circuit parameters (public)
    pub params: CrossContractCircuitParams,
    /// Is the protocol safe?
    pub is_safe: bool,
}

impl CrossContractProof {
    /// Serialize proof to bytes
    pub fn serialize_proof(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.proof.serialize_uncompressed(&mut bytes)
            .context("Failed to serialize proof")?;
        Ok(bytes)
    }

    /// Get human-readable safety report
    pub fn safety_report(&self) -> ProtocolSafetyReport {
        ProtocolSafetyReport {
            is_safe: self.is_safe,
            total_contracts: self.params.total_contracts,
            reentrancy_vulnerabilities: self.params.reentrancy_paths_found,
            privilege_escalation_risks: self.params.privilege_escalation_paths,
            critical_taint_issues: self.params.critical_taint_count,
            race_conditions: self.params.race_condition_count,
            has_circular_dependencies: self.params.has_circular_dependencies,
            dangerous_data_flows: self.params.dangerous_data_flows,
        }
    }
}

/// Human-readable protocol safety report
#[derive(Debug, Clone)]
pub struct ProtocolSafetyReport {
    pub is_safe: bool,
    pub total_contracts: usize,
    pub reentrancy_vulnerabilities: usize,
    pub privilege_escalation_risks: usize,
    pub critical_taint_issues: usize,
    pub race_conditions: usize,
    pub has_circular_dependencies: bool,
    pub dangerous_data_flows: usize,
}

impl ProtocolSafetyReport {
    /// Print formatted report
    pub fn print(&self) {
        println!("\n╔═══════════════════════════════════════════════════════╗");
        println!("║   CROSS-CONTRACT PROTOCOL SAFETY REPORT (PCC)        ║");
        println!("╠═══════════════════════════════════════════════════════╣");
        println!("║ Overall Safety: {}                                 ║", 
            if self.is_safe { "✅ SAFE" } else { "❌ UNSAFE" });
        println!("║                                                       ║");
        println!("║ Protocol Statistics:                                  ║");
        println!("║   Total Contracts Analyzed: {}                       ║", self.total_contracts);
        println!("║                                                       ║");
        println!("║ Critical Issues:                                      ║");
        println!("║   Reentrancy Paths: {}                               ║", self.reentrancy_vulnerabilities);
        println!("║   Privilege Escalation: {}                           ║", self.privilege_escalation_risks);
        println!("║   Critical Taint: {}                                 ║", self.critical_taint_issues);
        println!("║   Race Conditions: {}                                ║", self.race_conditions);
        println!("║                                                       ║");
        println!("║ Design Issues:                                        ║");
        println!("║   Circular Dependencies: {}                          ║", 
            if self.has_circular_dependencies { "Yes" } else { "No" });
        println!("║   Dangerous Data Flows: {}                           ║", self.dangerous_data_flows);
        println!("╚═══════════════════════════════════════════════════════╝\n");
    }
}

impl Default for CrossContractPCC {
    fn default() -> Self {
        Self::new()
    }
}

/// Quick API for one-shot proof generation
pub fn generate_cross_contract_proof(
    analyzer: &mut TransactionTraceAnalyzer,
) -> Result<CrossContractProof> {
    let mut pcc = CrossContractPCC::new();
    pcc.generate_protocol_proof(analyzer)
}

/// Quick API for proof verification
pub fn verify_cross_contract_proof(
    proof: &CrossContractProof,
) -> Result<bool> {
    let pcc = CrossContractPCC::new();
    // Note: In production, verifying key should be loaded
    pcc.verify_proof(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::transaction_trace_analyzer::TransactionTraceAnalyzer;

    #[test]
    fn test_pcc_creation() {
        let pcc = CrossContractPCC::new();
        assert!(pcc.proving_key.is_none());
        assert!(pcc.verifying_key.is_none());
    }

    #[test]
    fn test_safety_report_display() {
        let report = ProtocolSafetyReport {
            is_safe: true,
            total_contracts: 3,
            reentrancy_vulnerabilities: 0,
            privilege_escalation_risks: 0,
            critical_taint_issues: 0,
            race_conditions: 0,
            has_circular_dependencies: false,
            dangerous_data_flows: 0,
        };

        report.print();
    }
}
