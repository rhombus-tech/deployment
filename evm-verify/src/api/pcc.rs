// Proof-Carrying Code (PCC) API for EVM Verify
//
// This module provides functionality for generating and verifying proofs
// for Ethereum smart contracts using the Proof-Carrying Code approach.

use anyhow::{Result, Context};
use ethers::types::Bytes;
use ark_bn254::Bn254;
use ark_groth16::{Proof, generate_random_parameters, create_random_proof, prepare_verifying_key, verify_proof};
use ark_ec::pairing::Pairing;
use ark_std::rand::thread_rng;
use ark_relations::r1cs::ConstraintSynthesizer;

use crate::bytecode::BytecodeAnalyzer;
use crate::bytecode::security::SecurityWarning;
use crate::api::types::{Vulnerability, VulnerabilityType, VulnerabilitySeverity, VulnerabilityLocation};
use crate::bytecode::analyzer::VulnerabilityType as AnalyzerVulnerabilityType;
// Updated to use the external pcc crate
extern crate pcc;
use ::pcc::circuits::bytecode::BytecodeSafetyCircuit;

// Define Fr as the scalar field for Bn254
type Fr = <Bn254 as Pairing>::ScalarField;

/// Analyze bytecode for vulnerabilities using PCC
pub fn analyze_bytecode(bytecode: &Bytes) -> Result<Vec<Vulnerability>> {
    // Create a bytecode analyzer
    let analyzer = BytecodeAnalyzer::new(bytecode.to_vec());
    
    // Perform analysis
    let analysis_results = analyzer.analyze()?;
    
    // Convert security warnings to vulnerabilities
    let vulnerabilities = convert_warnings_to_vulnerabilities(&analysis_results.security_warnings);
    
    Ok(vulnerabilities)
}

/// Generate a proof for the security properties of the bytecode
pub fn generate_proof(bytecode: &Bytes) -> Result<Proof<Bn254>> {
    // Create a bytecode analyzer
    let analyzer = BytecodeAnalyzer::new(bytecode.to_vec());
    
    // Perform analysis
    let analysis_results = analyzer.analyze()?;
    
    // Convert analyzer vulnerability types to circuit vulnerability types
    let vulnerability_types = convert_analyzer_to_circuit_vulnerabilities(&analysis_results.security_warnings);
    
    // Calculate gas usage and complexity
    let gas_usage = analysis_results.gas_usage;
    let complexity = analysis_results.complexity;
    
    // Calculate bytecode hash
    let mut bytecode_hash = [0u8; 32];
    let mut keccak = tiny_keccak::Keccak::v256();
    keccak.update(bytecode.as_ref());
    keccak.finalize(&mut bytecode_hash);
    
    // Create a bytecode safety circuit with the actual bytecode
    let circuit = BytecodeSafetyCircuit::<Fr>::new_with_bytecode(
        &vulnerability_types,
        gas_usage,
        complexity,
        Some(bytecode_hash),
        bytecode.to_vec()
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
    let analyzer = BytecodeAnalyzer::new(bytecode.to_vec());
    
    // Perform analysis
    let analysis_results = analyzer.analyze()?;
    
    // Convert analyzer vulnerability types to circuit vulnerability types
    let vulnerability_types = convert_analyzer_to_circuit_vulnerabilities(&analysis_results.security_warnings);
    
    // Calculate gas usage and complexity
    let gas_usage = analysis_results.gas_usage;
    let complexity = analysis_results.complexity;
    
    // Calculate bytecode hash
    let mut bytecode_hash = [0u8; 32];
    let mut keccak = tiny_keccak::Keccak::v256();
    keccak.update(bytecode.as_ref());
    keccak.finalize(&mut bytecode_hash);
    
    // Create a bytecode safety circuit with the actual bytecode
    let circuit = BytecodeSafetyCircuit::<Fr>::new_with_bytecode(
        &vulnerability_types,
        gas_usage,
        complexity,
        Some(bytecode_hash),
        bytecode.to_vec()
    );
    
    // Generate parameters for the circuit
    let params = generate_random_parameters::<Bn254, _, _>(circuit, &mut thread_rng())?;
    
    // Prepare verifying key
    let pvk = prepare_verifying_key(&params.vk);
    
    // Verify the proof
    let result = verify_proof(&pvk, proof, &[])?;
    
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
                crate::bytecode::security::SecurityWarningKind::AccessControl => VulnerabilityType::AccessControl,
                crate::bytecode::security::SecurityWarningKind::UncheckedCall => VulnerabilityType::UncheckedCall,
                crate::bytecode::security::SecurityWarningKind::GasLimit => VulnerabilityType::GasLimit,
                crate::bytecode::security::SecurityWarningKind::TxOrigin => VulnerabilityType::TxOrigin,
                crate::bytecode::security::SecurityWarningKind::SelfDestruct => VulnerabilityType::SelfDestruct,
                crate::bytecode::security::SecurityWarningKind::DelegateCall => VulnerabilityType::DelegateCall,
                crate::bytecode::security::SecurityWarningKind::TimestampDependency => VulnerabilityType::TimestampDependency,
                crate::bytecode::security::SecurityWarningKind::FrontRunning => VulnerabilityType::FrontRunning,
                crate::bytecode::security::SecurityWarningKind::BlockNumberDependence => VulnerabilityType::BlockNumberDependency,
                crate::bytecode::security::SecurityWarningKind::UninitializedStorage => VulnerabilityType::UninitializedStorage,
                crate::bytecode::security::SecurityWarningKind::FlashLoan => VulnerabilityType::FlashLoan,
                crate::bytecode::security::SecurityWarningKind::SignatureReplay => VulnerabilityType::SignatureReplay,
                crate::bytecode::security::SecurityWarningKind::ProxyVulnerability => VulnerabilityType::ProxyVulnerability,
                crate::bytecode::security::SecurityWarningKind::OracleManipulation => VulnerabilityType::OracleManipulation,
                crate::bytecode::security::SecurityWarningKind::GovernanceVulnerability => VulnerabilityType::GovernanceVulnerability,
                crate::bytecode::security::SecurityWarningKind::MEVVulnerability => VulnerabilityType::Unknown,
                crate::bytecode::security::SecurityWarningKind::PriceManipulation => VulnerabilityType::Unknown,
                crate::bytecode::security::SecurityWarningKind::BitMaskVulnerability => VulnerabilityType::Unknown,
                crate::bytecode::security::SecurityWarningKind::GasOptimization => VulnerabilityType::Unknown,
                _ => VulnerabilityType::Unknown,
            };
            
            let location = match warning.pc {
                Some(pc) => VulnerabilityLocation::ProgramCounter(pc),
                None => VulnerabilityLocation::Unknown,
            };
            
            Vulnerability {
                title: warning.title.clone(),
                description: warning.description.clone(),
                severity: VulnerabilitySeverity::from_warning(&warning.description),
                vulnerability_type,
                location,
                recommendation: warning.recommendation.clone(),
            }
        })
        .collect()
}

/// Convert analyzer vulnerability types to circuit vulnerability types
fn convert_analyzer_to_circuit_vulnerabilities(warnings: &[SecurityWarning]) -> Vec<AnalyzerVulnerabilityType> {
    let mut vulnerability_types = Vec::new();
    
    for warning in warnings {
        match warning.kind {
            crate::bytecode::security::SecurityWarningKind::Reentrancy => {
                vulnerability_types.push(AnalyzerVulnerabilityType::Reentrancy);
            },
            crate::bytecode::security::SecurityWarningKind::IntegerOverflow => {
                vulnerability_types.push(AnalyzerVulnerabilityType::IntegerOverflow);
            },
            crate::bytecode::security::SecurityWarningKind::UnboundedOperation => {
                vulnerability_types.push(AnalyzerVulnerabilityType::UnboundedLoop);
            },
            crate::bytecode::security::SecurityWarningKind::UncheckedCall => {
                vulnerability_types.push(AnalyzerVulnerabilityType::UncheckedCall);
            },
            crate::bytecode::security::SecurityWarningKind::AccessControl => {
                vulnerability_types.push(AnalyzerVulnerabilityType::AccessControl);
            },
            crate::bytecode::security::SecurityWarningKind::OracleManipulation => {
                vulnerability_types.push(AnalyzerVulnerabilityType::OracleManipulation);
            },
            crate::bytecode::security::SecurityWarningKind::MEVVulnerability => {
                vulnerability_types.push(AnalyzerVulnerabilityType::MEVVulnerability);
            },
            crate::bytecode::security::SecurityWarningKind::FrontRunning => {
                vulnerability_types.push(AnalyzerVulnerabilityType::FrontRunning);
            },
            crate::bytecode::security::SecurityWarningKind::PriceManipulation => {
                vulnerability_types.push(AnalyzerVulnerabilityType::PriceManipulation);
            },
            crate::bytecode::security::SecurityWarningKind::BlockNumberDependence => {
                vulnerability_types.push(AnalyzerVulnerabilityType::BlockNumberDependence);
            },
            crate::bytecode::security::SecurityWarningKind::UninitializedStorage => {
                vulnerability_types.push(AnalyzerVulnerabilityType::UninitializedStorage);
            },
            crate::bytecode::security::SecurityWarningKind::GovernanceVulnerability => {
                vulnerability_types.push(AnalyzerVulnerabilityType::GovernanceVulnerability);
            },
            crate::bytecode::security::SecurityWarningKind::BitMaskVulnerability => {
                vulnerability_types.push(AnalyzerVulnerabilityType::BitMaskVulnerability);
            },
            _ => {
                // Other vulnerability types not yet supported in the circuit
                println!("Warning: Unsupported vulnerability type in circuit: {:?}", warning.kind);
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
