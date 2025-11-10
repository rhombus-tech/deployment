// Proof-Carrying Code (PCC) API for EVM Verify
//
// This module provides functionality for generating and verifying proofs
// for Ethereum smart contracts using the Proof-Carrying Code approach.

use anyhow::{Result, Context};
use ethers::types::{Bytes, U256};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Proof, generate_random_parameters, create_random_proof, prepare_verifying_key, verify_proof as ark_verify_proof};
use ark_std::rand::thread_rng;
use ark_relations::r1cs::ConstraintSynthesizer;
use tiny_keccak::{Hasher, Keccak};

use crate::bytecode::BytecodeAnalyzer;
use crate::bytecode::security::SecurityWarning;
use crate::api::types::{Vulnerability, VulnerabilityType, VulnerabilitySeverity, VulnerabilityLocation};
// Updated to use the external pcc crate
extern crate pcc;
use ::pcc::circuits::bytecode::BytecodeSafetyCircuit;
use ::pcc::analyzer::bytecode::VulnerabilityType as PccVulnerabilityType;

/// Analyze bytecode for vulnerabilities using PCC
pub fn analyze_bytecode(bytecode: &Bytes) -> Result<Vec<Vulnerability>> {
    // Create a bytecode analyzer
    let mut analyzer = BytecodeAnalyzer::new(bytecode.clone());
    
    // Perform analysis
    let analysis_results = analyzer.analyze()?;
    
    // Convert security warnings to vulnerabilities
    let vulnerabilities = convert_warnings_to_vulnerabilities(&analysis_results.security_warnings);
    
    Ok(vulnerabilities)
}

/// Generate a proof for the security properties of the bytecode
pub fn generate_proof(bytecode: &Bytes) -> Result<Proof<Bn254>> {
    // Create a bytecode analyzer
    let mut analyzer = BytecodeAnalyzer::new(bytecode.clone());
    
    // Perform analysis
    let analysis_results = analyzer.analyze()?;
    
    // Convert analyzer vulnerability types to circuit vulnerability types
    let vulnerability_types = convert_analyzer_to_circuit_vulnerabilities(&analysis_results.security_warnings);
    
    // Calculate gas usage and complexity
    let gas_usage = analysis_results.gas_usage;
    let complexity = bytecode.len() as u32; // Use bytecode length as complexity
    
    // Calculate bytecode hash
    let mut bytecode_hash = [0u8; 32];
    let mut keccak = Keccak::v256();
    keccak.update(bytecode.as_ref());
    keccak.finalize(&mut bytecode_hash);
    
    // Create a bytecode safety circuit with the actual bytecode
    let circuit = BytecodeSafetyCircuit::<Fr>::new(
        &vulnerability_types,
        U256::from(gas_usage),
        complexity,
        bytecode.to_vec(),
        Some(bytecode_hash.to_vec())
    );
    
    // Generate parameters for the circuit
    let params = generate_random_parameters::<Bn254, _, _>(circuit.clone(), &mut thread_rng())?;
    
    // Create a proof
    let proof = create_random_proof(circuit, &params, &mut thread_rng())?;
    
    Ok(proof)
}

/// Verify a proof for the security properties of the bytecode
pub fn verify_proof(bytecode: &Bytes, proof: &Proof<Bn254>) -> Result<bool> {
    // Create a bytecode analyzer
    let mut analyzer = BytecodeAnalyzer::new(bytecode.clone());
    
    // Perform analysis
    let analysis_results = analyzer.analyze()?;
    
    // Convert analyzer vulnerability types to circuit vulnerability types
    let vulnerability_types = convert_analyzer_to_circuit_vulnerabilities(&analysis_results.security_warnings);
    
    // Calculate gas usage and complexity
    let gas_usage = analysis_results.gas_usage;
    let complexity = bytecode.len() as u32; // Use bytecode length as complexity
    
    // Calculate bytecode hash
    let mut bytecode_hash = [0u8; 32];
    let mut keccak = Keccak::v256();
    keccak.update(bytecode.as_ref());
    keccak.finalize(&mut bytecode_hash);
    
    // Create a bytecode safety circuit with the actual bytecode
    let circuit = BytecodeSafetyCircuit::<Fr>::new(
        &vulnerability_types,
        U256::from(gas_usage),
        complexity,
        bytecode.to_vec(),
        Some(bytecode_hash.to_vec())
    );
    
    // Generate parameters for the circuit
    let params = generate_random_parameters::<Bn254, _, _>(circuit, &mut thread_rng())?;
    
    // Prepare verifying key
    let pvk = prepare_verifying_key(&params.vk);
    
    // Verify the proof with empty public inputs
    let result = ark_verify_proof(&pvk, proof, &[])?;
    
    Ok(result)
}

/// Convert security warnings to vulnerabilities
fn convert_warnings_to_vulnerabilities(warnings: &[SecurityWarning]) -> Vec<Vulnerability> {
    warnings.iter()
        .map(|warning| {
            let vulnerability_type = match warning.kind {
                crate::bytecode::security::SecurityWarningKind::Reentrancy => VulnerabilityType::Reentrancy,
                crate::bytecode::security::SecurityWarningKind::IntegerOverflow => VulnerabilityType::IntegerOverflow,
                crate::bytecode::security::SecurityWarningKind::IntegerUnderflow => VulnerabilityType::IntegerUnderflow,
                crate::bytecode::security::SecurityWarningKind::AccessControlVulnerability => VulnerabilityType::AccessControl,
                crate::bytecode::security::SecurityWarningKind::WeakAccessControl => VulnerabilityType::AccessControl,
                crate::bytecode::security::SecurityWarningKind::UncheckedExternalCall => VulnerabilityType::UncheckedCall,
                crate::bytecode::security::SecurityWarningKind::UncheckedCallReturn => VulnerabilityType::UncheckedCall,
                crate::bytecode::security::SecurityWarningKind::GasLimitIssue => VulnerabilityType::GasLimit,
                crate::bytecode::security::SecurityWarningKind::TxOriginUsage => VulnerabilityType::TxOrigin,
                crate::bytecode::security::SecurityWarningKind::TxOriginAuth => VulnerabilityType::TxOrigin,
                crate::bytecode::security::SecurityWarningKind::UnprotectedSelfDestruct => VulnerabilityType::SelfDestruct,
                crate::bytecode::security::SecurityWarningKind::UnprotectedDelegateCall => VulnerabilityType::DelegateCall,
                crate::bytecode::security::SecurityWarningKind::DelegateCallMisuse => VulnerabilityType::DelegateCall,
                crate::bytecode::security::SecurityWarningKind::TimestampDependence => VulnerabilityType::TimestampDependency,
                crate::bytecode::security::SecurityWarningKind::FrontRunning => VulnerabilityType::FrontRunning,
                crate::bytecode::security::SecurityWarningKind::TransactionOrderingDependency => VulnerabilityType::TransactionOrderingDependency,
                crate::bytecode::security::SecurityWarningKind::MissingTransactionOrderingProtection => VulnerabilityType::MissingTransactionOrderingProtection,
                crate::bytecode::security::SecurityWarningKind::SandwichAttackVulnerability => VulnerabilityType::SandwichAttackVulnerability,
                crate::bytecode::security::SecurityWarningKind::BlockNumberDependence => VulnerabilityType::BlockNumberDependency,
                crate::bytecode::security::SecurityWarningKind::UninitializedStorage => VulnerabilityType::UninitializedStorage,
                crate::bytecode::security::SecurityWarningKind::FlashLoanVulnerability => VulnerabilityType::FlashLoan,
                crate::bytecode::security::SecurityWarningKind::FlashLoanStateManipulation => VulnerabilityType::FlashLoan,
                crate::bytecode::security::SecurityWarningKind::SignatureReplay => VulnerabilityType::SignatureReplay,
                crate::bytecode::security::SecurityWarningKind::UninitializedProxy => VulnerabilityType::ProxyVulnerability,
                crate::bytecode::security::SecurityWarningKind::StorageCollision => VulnerabilityType::ProxyVulnerability,
                crate::bytecode::security::SecurityWarningKind::OracleManipulation => VulnerabilityType::OracleManipulation,
                crate::bytecode::security::SecurityWarningKind::WeakQuorumRequirement => VulnerabilityType::GovernanceVulnerability,
                crate::bytecode::security::SecurityWarningKind::InsufficientTimelock => VulnerabilityType::GovernanceVulnerability,
                crate::bytecode::security::SecurityWarningKind::FlashLoanVotingVulnerability => VulnerabilityType::GovernanceVulnerability,
                crate::bytecode::security::SecurityWarningKind::WeakRandomness => VulnerabilityType::TimestampDependency,
                crate::bytecode::security::SecurityWarningKind::MEVVulnerability => VulnerabilityType::MevVulnerability,
                crate::bytecode::security::SecurityWarningKind::PriceManipulation => VulnerabilityType::PriceManipulation,
                crate::bytecode::security::SecurityWarningKind::BitMaskVulnerability => VulnerabilityType::Unknown,
                _ => VulnerabilityType::Unknown,
            };
            
            // Use ProgramCounter variant for bytecode location
            let location = VulnerabilityLocation::ProgramCounter(0);
            
            Vulnerability {
                title: format!("{:?} Detected", vulnerability_type),
                description: warning.description.clone(),
                severity: VulnerabilitySeverity::from_warning(&warning.description),
                vulnerability_type,
                location,
                recommendation: format!("Review and fix {:?} vulnerability", vulnerability_type),
            }
        })
        .collect()
}

/// Convert analyzer vulnerability types to circuit vulnerability types
fn convert_analyzer_to_circuit_vulnerabilities(warnings: &[SecurityWarning]) -> Vec<PccVulnerabilityType> {
    let mut vulnerability_types = Vec::new();
    
    for warning in warnings {
        match warning.kind {
            crate::bytecode::security::SecurityWarningKind::Reentrancy => {
                vulnerability_types.push(PccVulnerabilityType::Reentrancy);
            },
            crate::bytecode::security::SecurityWarningKind::IntegerOverflow => {
                vulnerability_types.push(PccVulnerabilityType::IntegerOverflow);
            },
            crate::bytecode::security::SecurityWarningKind::DenialOfService => {
                vulnerability_types.push(PccVulnerabilityType::UnboundedLoop);
            },
            crate::bytecode::security::SecurityWarningKind::UncheckedExternalCall => {
                vulnerability_types.push(PccVulnerabilityType::UncheckedCall);
            },
            crate::bytecode::security::SecurityWarningKind::UncheckedCallReturn => {
                vulnerability_types.push(PccVulnerabilityType::UncheckedCall);
            },
            crate::bytecode::security::SecurityWarningKind::AccessControlVulnerability => {
                vulnerability_types.push(PccVulnerabilityType::AccessControl);
            },
            crate::bytecode::security::SecurityWarningKind::WeakAccessControl => {
                vulnerability_types.push(PccVulnerabilityType::AccessControl);
            },
            crate::bytecode::security::SecurityWarningKind::OracleManipulation => {
                vulnerability_types.push(PccVulnerabilityType::OracleManipulation);
            },
            crate::bytecode::security::SecurityWarningKind::MEVVulnerability => {
                vulnerability_types.push(PccVulnerabilityType::MevVulnerability);
            },
            crate::bytecode::security::SecurityWarningKind::FrontRunning => {
                vulnerability_types.push(PccVulnerabilityType::FrontRunning);
            },
            crate::bytecode::security::SecurityWarningKind::PriceManipulation => {
                vulnerability_types.push(PccVulnerabilityType::PriceManipulation);
            },
            crate::bytecode::security::SecurityWarningKind::BlockNumberDependence => {
                vulnerability_types.push(PccVulnerabilityType::BlockNumberDependence);
            },
            crate::bytecode::security::SecurityWarningKind::UninitializedStorage => {
                vulnerability_types.push(PccVulnerabilityType::UninitializedStorage);
            },
            crate::bytecode::security::SecurityWarningKind::WeakQuorumRequirement => {
                vulnerability_types.push(PccVulnerabilityType::GovernanceVulnerability);
            },
            crate::bytecode::security::SecurityWarningKind::InsufficientTimelock => {
                vulnerability_types.push(PccVulnerabilityType::GovernanceVulnerability);
            },
            crate::bytecode::security::SecurityWarningKind::BitMaskVulnerability => {
                vulnerability_types.push(PccVulnerabilityType::BitmaskVulnerability);
            },
            crate::bytecode::security::SecurityWarningKind::TimestampDependence => {
                vulnerability_types.push(PccVulnerabilityType::BlockNumberDependence);
            },
            crate::bytecode::security::SecurityWarningKind::BlockTimestampDependency => {
                vulnerability_types.push(PccVulnerabilityType::BlockNumberDependence);
            },
            crate::bytecode::security::SecurityWarningKind::UnsafeTimestampComparison => {
                vulnerability_types.push(PccVulnerabilityType::BlockNumberDependence);
            },
            crate::bytecode::security::SecurityWarningKind::TimeBasedRandomness => {
                vulnerability_types.push(PccVulnerabilityType::WeakRandomness);
            },
            _ => {
                // Other vulnerability types not yet supported in the circuit
                // Just use a generic vulnerability type
                vulnerability_types.push(PccVulnerabilityType::Other(255));
            }
        }
    }
    
    vulnerability_types
}

/// Sample vulnerabilities for testing
pub fn sample_vulnerabilities() -> Vec<Vulnerability> {
    vec![
        Vulnerability {
            title: "Reentrancy Vulnerability".to_string(),
            description: "The contract may be vulnerable to reentrancy attacks".to_string(),
            severity: VulnerabilitySeverity::High,
            vulnerability_type: VulnerabilityType::Reentrancy,
            location: VulnerabilityLocation::ProgramCounter(42),
            recommendation: "Use ReentrancyGuard or check-effects-interactions pattern".to_string(),
        },
        Vulnerability {
            title: "Integer Overflow".to_string(),
            description: "Possible integer overflow in arithmetic operation".to_string(),
            severity: VulnerabilitySeverity::Medium,
            vulnerability_type: VulnerabilityType::IntegerOverflow,
            location: VulnerabilityLocation::ProgramCounter(123),
            recommendation: "Use SafeMath or Solidity 0.8+ with built-in overflow checks".to_string(),
        },
    ]
}
