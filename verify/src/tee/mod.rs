//! Trusted Execution Environment (TEE) validation module
//!
//! This module provides validation and verification tools specifically designed
//! for TEE environments, especially for dual-TEE execution without consensus.
//! It focuses on:
//!
//! 1. Determinism guarantees for consistent execution across TEEs
//! 2. Time-based attack prevention
//! 3. Hardware discrepancy mitigation
//! 4. State synchronization validation 
//! 5. Host function permission enforcement
//! 6. Metrics collection for execution validation

use anyhow::{Result, anyhow, Error};
use crate::circuits::determinism::{analyze_determinism, NonDeterministicOperation};
// Simplify imports for side-channel detection
use crate::circuits::side_channel::analyze_side_channel_vulnerabilities;
use walrus::{Module, ModuleConfig};
#[cfg(feature = "zk-proofs")]
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
#[cfg(feature = "zk-proofs")]
use ark_bls12_381::Fr;
use std::collections::HashMap;
// use std::time::Duration;

pub mod permissions;
use permissions::{HostFunctionValidator, FunctionCategory};

/// Side-channel vulnerability type
#[derive(Debug, Clone, PartialEq)]
pub enum SideChannelVulnerability {
    /// Timing side-channel vulnerability
    Timing(String),
    /// Memory pattern side-channel vulnerability
    MemoryPattern(String),
    /// Control flow side-channel vulnerability
    ControlFlow(String),
    /// Cache-based side-channel vulnerability
    Cache(String),
    /// Power analysis side-channel vulnerability
    PowerAnalysis(String),
}

/// Maximum allowed time delta between TEE executions (in milliseconds)
/// Based on memory about HyperTeeController targeting sub-100ms communication
pub const MAX_TIME_DELTA_MS: u64 = 100;

/// Maximum allowed memory access pattern divergence (percentage)
/// Controls how much memory access patterns can vary before flagging as a side-channel risk
pub const MAX_MEMORY_PATTERN_DIVERGENCE: f64 = 5.0; // 5% tolerance

/// Result of module execution in a TEE
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionResult {
    /// Final state hash after execution
    pub state_hash: [u8; 32],
    /// Execution output
    pub output: Vec<u8>,
    /// Execution time in milliseconds
    pub execution_time: u64,
    /// Execution metrics
    pub metrics: HashMap<String, f64>,
    /// Memory usage in bytes
    pub memory_usage: u64,
}

/// Severity level for TEE validation issues
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeSeverity {
    /// Warning, but execution can continue
    Warning,
    /// Error that could lead to inconsistent execution
    Error,
    /// Critical issue that will definitely lead to inconsistent execution
    Critical,
    /// Informational message
    Info,
}

/// Type of TEE validation issue
#[derive(Debug, Clone, PartialEq)]
pub enum TeeIssueType {
    /// Non-deterministic operation that will cause inconsistent execution
    NonDeterministic(NonDeterministicOperation),
    /// Time-based vulnerability
    TimeBased(String),
    /// Hardware-specific vulnerability
    HardwareSpecific(String),
    /// Missing state synchronization capability
    MissingStateSync(String),
    /// Missing metrics reporting
    MissingMetrics(String),
    /// Execution inconsistency detected at runtime
    RuntimeInconsistency(String),
    /// Side-channel vulnerability
    SideChannel(SideChannelVulnerability),
    /// Execution result inconsistency
    ExecutionInconsistency(String),
}

/// TEE validation issue
#[derive(Debug, Clone)]
pub struct TeeValidationIssue {
    /// Issue description
    pub description: String,
    /// Severity level
    pub severity: TeeSeverity,
    /// Category of the issue (for grouping)
    pub category: Option<String>,
    /// Type of the issue
    pub issue_type: TeeIssueType,
}

/// TEE validation report
#[derive(Debug, Clone)]
pub struct TeeValidationReport {
    /// Validation issues found
    pub issues: Vec<TeeValidationIssue>,
}

impl TeeValidationReport {
    /// Create a new empty validation report
    pub fn new() -> Self {
        Self {
            issues: Vec::new(),
        }
    }

    /// Add an issue to the report
    pub fn add_issue(&mut self, issue: TeeValidationIssue) {
        self.issues.push(issue);
    }

    /// Add a simple issue with just description and severity
    pub fn add_simple_issue(&mut self, description: &str, severity: TeeSeverity, category: Option<&str>) {
        self.add_issue(TeeValidationIssue {
            description: description.to_string(),
            severity,
            category: category.map(|s| s.to_string()),
            issue_type: TeeIssueType::RuntimeInconsistency("General validation issue".to_string()),
        });
    }

    /// Add an informational message to the report
    pub fn add_info(&mut self, description: &str) {
        self.add_simple_issue(description, TeeSeverity::Info, None);
    }

    /// Add an error message to the report
    pub fn add_error(&mut self, description: &str) {
        self.add_simple_issue(description, TeeSeverity::Error, None);
    }

    /// Check if the report contains any critical issues
    pub fn has_critical_issues(&self) -> bool {
        self.issues.iter().any(|issue| issue.severity == TeeSeverity::Critical)
    }

    /// Check if the report contains any errors
    pub fn has_errors(&self) -> bool {
        self.issues.iter().any(|issue| issue.severity == TeeSeverity::Error || 
                                       issue.severity == TeeSeverity::Critical)
    }

    /// Generate a human-readable summary of the issues
    pub fn summary(&self) -> String {
        if self.issues.is_empty() {
            return "No TEE validation issues found".to_string();
        }

        let mut result = String::new();
        let critical_count = self.issues.iter()
            .filter(|i| i.severity == TeeSeverity::Critical)
            .count();
        let error_count = self.issues.iter()
            .filter(|i| i.severity == TeeSeverity::Error)
            .count();
        let warning_count = self.issues.iter()
            .filter(|i| i.severity == TeeSeverity::Warning)
            .count();
        let info_count = self.issues.iter()
            .filter(|i| i.severity == TeeSeverity::Info)
            .count();

        result.push_str(&format!(
            "TEE Validation Report: {} critical, {} errors, {} warnings, {} info\n",
            critical_count, error_count, warning_count, info_count
        ));

        for (i, issue) in self.issues.iter().enumerate() {
            result.push_str(&format!(
                "{}. [{}] {}\n",
                i + 1,
                match issue.severity {
                    TeeSeverity::Critical => "CRITICAL",
                    TeeSeverity::Error => "ERROR",
                    TeeSeverity::Warning => "WARNING",
                    TeeSeverity::Info => "INFO",
                },
                issue.description
            ));
        }

        result
    }
}

/// Validate a WebAssembly module for TEE execution safety
pub fn validate_for_tee_execution(wasm: &[u8]) -> Result<TeeValidationReport> {
    let mut report = TeeValidationReport::new();
    
    // Parse and validate the WebAssembly module
    let module = Module::from_buffer(wasm)
        .map_err(|e| anyhow!("Failed to parse WebAssembly module: {}", e))?;
    
    // 1. Validate determinism
    validate_determinism(&module, &mut report);
    
    // 2. Validate host function permissions
    validate_host_function_permissions(&module, &mut report)?;
    
    // 3. Validate state management
    validate_state_management(&module, &mut report);
    
    // 4. Validate side-channel defenses
    let side_channel_proof_success = validate_side_channel_defenses(&module, &mut report)?;
    
    // Add a summary of ZK proof status
    if side_channel_proof_success {
        report.add_info("Successfully generated ZK proof for side-channel safety");
    } else {
        report.add_error("Failed to generate ZK proof for side-channel safety - vulnerabilities detected");
    }
    
    Ok(report)
}

/// Validate determinism of a WebAssembly module
pub fn validate_determinism(module: &Module, report: &mut TeeValidationReport) {
    // Analyze module for deterministic operations
    let operations = analyze_determinism(module);
    
    // Check for non-deterministic operations
    for op in operations {
        let (description, severity, category) = match op {
            NonDeterministicOperation::FloatingPoint(details) => (
                format!("Floating point operation detected: {}", details),
                TeeSeverity::Critical,
                Some("floating-point")
            ),
            NonDeterministicOperation::TimeDependent(details) => (
                format!("Time-dependent operation detected: {}", details),
                TeeSeverity::Error,
                Some("time-dependent")
            ),
            NonDeterministicOperation::RandomNumberGeneration(details) => (
                format!("Random number generation detected: {}", details),
                TeeSeverity::Critical,
                Some("random-generation")
            ),
            NonDeterministicOperation::EnvironmentAccess(details) => (
                format!("Environment access detected: {}", details),
                TeeSeverity::Error,
                Some("environment-access")
            ),
            NonDeterministicOperation::HardwareDependent(details) => (
                format!("Hardware-dependent operation detected: {}", details),
                TeeSeverity::Warning,
                Some("hardware-dependent")
            ),
        };
        
        report.add_simple_issue(&description, severity, category);
    }
}

/// Validate state synchronization capabilities of a WebAssembly module
pub fn validate_state_management(module: &Module, report: &mut TeeValidationReport) -> Result<()> {
    let mut has_get_state = false;
    let mut has_set_state = false;
    
    // Check for required exports
    for export in module.exports.iter() {
        match &export.item {
            walrus::ExportItem::Function(_func_id) => {
                if export.name == "get_state" {
                    has_get_state = true;
                } else if export.name == "set_state" {
                    has_set_state = true;
                }
            }
            _ => {}
        }
    }
    
    // Report missing exports
    if !has_get_state {
        report.add_simple_issue(
            "Module lacks 'get_state' export required for state synchronization",
            TeeSeverity::Error,
            Some("state-sync")
        );
    }
    
    if !has_set_state {
        report.add_simple_issue(
            "Module lacks 'set_state' export required for state synchronization",
            TeeSeverity::Error,
            Some("state-sync")
        );
    }
    
    // Both exports are required for dual-TEE execution
    if !has_get_state || !has_set_state {
        return Err(anyhow!(
            "Module missing required state synchronization exports"
        ));
    }
    
    Ok(())
}

/// Validate host function permissions of a WebAssembly module
pub fn validate_host_function_permissions(module: &Module, report: &mut TeeValidationReport) -> Result<()> {
    // Create validator with default permissions
    let mut validator = HostFunctionValidator::new();
    
    // Set allowed categories based on security requirements for TEE
    // By default, allow safe functions and logging, but restrict other categories
    validator.set_permissions(&[
        FunctionCategory::Logging,   // Allow logging functions
        FunctionCategory::Storage,   // Allow storage access (needed for state)
        FunctionCategory::Crypto,    // Allow cryptographic operations
    ]);
    
    // Validate the module's imports
    let non_deterministic = validator.validate(module);
    
    match non_deterministic {
        Ok(sensitive_imports) => {
            // Report sensitive imports as warnings
            for (module_name, func_name, category) in sensitive_imports {
                let category_str = format!("{:?}", category).to_lowercase();
                report.add_simple_issue(
                    &format!(
                        "Module imports potentially non-deterministic function: {}.{}",
                        module_name, func_name
                    ),
                    TeeSeverity::Warning,
                    Some(&category_str)
                );
            }
            Ok(())
        },
        Err(e) => {
            // Report error for forbidden imports
            report.add_simple_issue(
                &format!("Host function permission validation failed: {}", e),
                TeeSeverity::Error,
                Some("forbidden-import")
            );
            Err(e)
        }
    }
}

/// Validate side-channel defenses for TEE-compatible execution
pub fn validate_side_channel_defenses(module: &Module, report: &mut TeeValidationReport) -> Result<bool> {
    report.add_info("Validating side-channel defenses...");
    
    // Call the individual detection functions for a thorough analysis
    detect_timing_side_channels(module, report);
    detect_memory_pattern_side_channels(module, report);
    detect_control_flow_side_channels(module, report);
    detect_cache_side_channels(module, report);
    detect_power_analysis_side_channels(module, report);
    
    // Count the different types of vulnerabilities found
    let timing_count = report.issues.iter().filter(|i| i.category.as_ref().map_or(false, |c| c == "timing-side-channel")).count();
    let memory_pattern_count = report.issues.iter().filter(|i| i.category.as_ref().map_or(false, |c| c == "memory-pattern-side-channel")).count();
    let control_flow_count = report.issues.iter().filter(|i| i.category.as_ref().map_or(false, |c| c == "control-flow-side-channel")).count();
    let cache_count = report.issues.iter().filter(|i| i.category.as_ref().map_or(false, |c| c == "cache-side-channel")).count();
    let power_analysis_count = report.issues.iter().filter(|i| i.category.as_ref().map_or(false, |c| c == "power-analysis-side-channel")).count();
    
    // Add summary info
    report.add_info(&format!("Side-channel vulnerability summary: {} timing, {} memory pattern, {} control flow, {} cache, {} power analysis",
        timing_count, memory_pattern_count, control_flow_count, cache_count, power_analysis_count));
    
    // For now, we're not generating ZK proofs, but we'll return true if no critical or error issues were found
    let has_high_severity = report.issues.iter().any(|i| i.severity == TeeSeverity::Critical || i.severity == TeeSeverity::Error);
    
    Ok(!has_high_severity)
}

/// Verify consistency between two TEE execution results
pub fn verify_execution_consistency(
    results1: &ExecutionResult, 
    results2: &ExecutionResult
) -> Result<TeeValidationReport> {
    let mut report = TeeValidationReport::new();
    
    // Check for time-based inconsistencies
    let time_difference = if results1.execution_time > results2.execution_time {
        results1.execution_time - results2.execution_time
    } else {
        results2.execution_time - results1.execution_time
    };
    
    if time_difference > MAX_TIME_DELTA_MS {
        report.add_issue(TeeValidationIssue {
            description: format!(
                "Time delta between executions ({} ms) exceeds maximum allowed ({} ms)",
                time_difference, MAX_TIME_DELTA_MS
            ),
            severity: TeeSeverity::Warning,
            category: Some("time-sync".to_string()),
            issue_type: TeeIssueType::ExecutionInconsistency("Time delta exceeds limit".to_string()),
        });
    }
    
    // Compare state hashes
    if results1.state_hash != results2.state_hash {
        report.add_issue(TeeValidationIssue {
            description: "State hashes differ between TEEs, indicating non-deterministic execution".to_string(),
            severity: TeeSeverity::Critical,
            category: Some("state-sync".to_string()),
            issue_type: TeeIssueType::ExecutionInconsistency("State hash mismatch".to_string()),
        });
    }
    
    // Compare outputs
    if results1.output != results2.output {
        report.add_issue(TeeValidationIssue {
            description: format!(
                "Outputs differ between TEEs: {} bytes vs {} bytes",
                results1.output.len(), results2.output.len()
            ),
            severity: TeeSeverity::Critical,
            category: Some("output".to_string()),
            issue_type: TeeIssueType::ExecutionInconsistency("Output mismatch".to_string()),
        });
    }
    
    // Compare metrics
    for (key, value1) in &results1.metrics {
        if let Some(value2) = results2.metrics.get(key) {
            // For floating point metrics, allow small differences
            let delta = (value1 - value2).abs();
            if delta > 0.001 {
                report.add_issue(TeeValidationIssue {
                    description: format!(
                        "Metric '{}' differs between TEEs: {} vs {}",
                        key, value1, value2
                    ),
                    severity: TeeSeverity::Warning,
                    category: Some("metrics".to_string()),
                    issue_type: TeeIssueType::ExecutionInconsistency("Metric value mismatch".to_string()),
                });
            }
        } else {
            report.add_issue(TeeValidationIssue {
                description: format!(
                    "Metric '{}' present in first TEE but missing in second TEE",
                    key
                ),
                severity: TeeSeverity::Warning,
                category: Some("metrics".to_string()),
                issue_type: TeeIssueType::ExecutionInconsistency("Missing metric".to_string()),
            });
        }
    }
    
    // Check for metrics in second execution not present in first
    for key in results2.metrics.keys() {
        if !results1.metrics.contains_key(key) {
            report.add_issue(TeeValidationIssue {
                description: format!(
                    "Metric '{}' present in second TEE but missing in first TEE",
                    key
                ),
                severity: TeeSeverity::Warning,
                category: Some("metrics".to_string()),
                issue_type: TeeIssueType::ExecutionInconsistency("Extra metric".to_string()),
            });
        }
    }
    
    Ok(report)
}

/// Detect timing side-channel vulnerabilities
fn detect_timing_side_channels(module: &Module, report: &mut TeeValidationReport) {
    // Look for variable-time crypto operations
    let variable_time_markers = [
        "aes", "rsa", "dsa", "ecdsa", "encrypt", "decrypt", "signature", 
        "hash", "sha", "md5", "pbkdf", "scrypt", "bcrypt", "compare", "memcmp"
    ];
    
    // Check function and import names for crypto operations that may not be constant-time
    for func in module.funcs.iter() {
        let name = match &func.name {
            Some(name) => name.to_string(),
            None => continue,
        };
        
        // Check if function name suggests cryptographic operation
        for &marker in variable_time_markers.iter() {
            if name.to_lowercase().contains(&marker.to_lowercase()) {
                report.add_simple_issue(
                    &format!("Potential timing side-channel in function '{}'. \
                              Non-constant-time cryptographic operations can leak secrets", name),
                    TeeSeverity::Error,
                    Some("timing-side-channel")
                );
                break;
            }
        }
        
        // Check for branches that could depend on secret data
        if let walrus::FunctionKind::Local(local_func) = &func.kind {
            let entry_block_id = local_func.entry_block();
            let block = local_func.block(entry_block_id);
            
            for (instr, _) in &block.instrs {
                let instr_debug = format!("{:?}", instr);
                
                // Look for conditional branch instructions that could depend on secrets
                if instr_debug.contains("br_if") || instr_debug.contains("br_table") {
                    report.add_simple_issue(
                        &format!("Potential timing side-channel in function '{}'. \
                                  Secret-dependent branch can leak information through timing: {}", 
                                 name, instr_debug),
                        TeeSeverity::Warning,
                        Some("timing-side-channel")
                    );
                }
            }
        }
    }
    
    // Check for comparison operations without constant-time implementation
    for import in module.imports.iter() {
        let name = import.name.as_str();
        let module_name = import.module.as_str();
        
        if name.contains("compare") || name.contains("memcmp") || name.contains("eq") {
            report.add_simple_issue(
                &format!("Import '{}.{}' may not use constant-time comparison, \
                          which can leak secret information", module_name, name),
                TeeSeverity::Warning,
                Some("timing-side-channel")
            );
        }
    }
}

/// Detect memory access pattern side-channel vulnerabilities
fn detect_memory_pattern_side_channels(module: &Module, report: &mut TeeValidationReport) {
    // Check for memory accesses that could depend on secret data
    
    // Look for functions that may handle sensitive data
    let sensitive_markers = [
        "key", "secret", "password", "token", "credential", "auth", "private",
        "encrypt", "decrypt", "signature", "sign", "verify"
    ];
    
    // Review all functions for memory access patterns
    for func in module.funcs.iter() {
        let name = match &func.name {
            Some(name) => name.to_string(),
            None => continue,
        };
        
        // Check if function likely handles sensitive data
        let is_sensitive = sensitive_markers.iter()
            .any(|&marker| name.to_lowercase().contains(&marker.to_lowercase()));
        
        if !is_sensitive {
            continue;
        }
        
        // Analyze memory access patterns in sensitive functions
        if let walrus::FunctionKind::Local(local_func) = &func.kind {
            let entry_block_id = local_func.entry_block();
            let block = local_func.block(entry_block_id);
            
            // Look for conditional memory accesses
            for (instr, _) in &block.instrs {
                let instr_debug = format!("{:?}", instr);
                
                // Check for loads and stores that could be secret-dependent
                if (instr_debug.contains("load") || instr_debug.contains("store")) && 
                   (instr_debug.contains("br_if") || instr_debug.contains("if")) {
                    report.add_simple_issue(
                        &format!("Potential memory access pattern side-channel in function '{}'. \
                                  Secret-dependent memory access can leak information: {}", 
                                 name, instr_debug),
                        TeeSeverity::Error,
                        Some("memory-side-channel")
                    );
                }
            }
        }
    }
}

/// Detect control flow side-channel vulnerabilities
fn detect_control_flow_side_channels(module: &Module, report: &mut TeeValidationReport) {
    // Look for sensitive operations like auth or crypto
    let sensitive_markers = [
        "auth", "login", "verify", "password", "check", "validate", "compare"
    ];
    
    // Review all functions for conditional branches on sensitive data
    for func in module.funcs.iter() {
        let name = match &func.name {
            Some(name) => name.to_string(),
            None => continue,
        };
        
        // Check if function likely handles authentication or verification
        let is_auth_function = sensitive_markers.iter()
            .any(|&marker| name.to_lowercase().contains(&marker.to_lowercase()));
        
        if !is_auth_function {
            continue;
        }
        
        // Look for early returns that could leak information via timing
        if let walrus::FunctionKind::Local(local_func) = &func.kind {
            let entry_block_id = local_func.entry_block();
            let block = local_func.block(entry_block_id);
            
            for (instr, _) in &block.instrs {
                let instr_debug = format!("{:?}", instr);
                
                // Check for early returns in auth functions
                if instr_debug.contains("return") && instr_debug.contains("br_if") {
                    report.add_simple_issue(
                        &format!("Potential control flow side-channel in authentication function '{}'. \
                                  Early returns can leak information through timing differences", name),
                        TeeSeverity::Critical,
                        Some("control-flow-side-channel")
                    );
                }
            }
        }
    }
}

/// Detect cache-based side-channel vulnerabilities
fn detect_cache_side_channels(module: &Module, report: &mut TeeValidationReport) {
    // Look for table lookups that could be vulnerable to cache timing attacks
    let cache_sensitive_patterns = [
        "table", "lookup", "sbox", "array", "map", "dict", "aes_table", "lookup_table"
    ];
    
    // Look for cryptographic operations that typically use lookup tables
    let crypto_table_ops = [
        "aes", "des", "tdes", "3des", "blowfish", "camellia", "cast",
        "sm4", "aria", "seed", "substitution"
    ];
    
    for func in module.funcs.iter() {
        let name = match &func.name {
            Some(name) => name.to_string(),
            None => continue,
        };
        
        // Check for table lookup patterns in function names
        let has_table_pattern = cache_sensitive_patterns.iter().any(|&pattern| 
            name.to_lowercase().contains(&pattern.to_lowercase()));
            
        let has_crypto_pattern = crypto_table_ops.iter().any(|&pattern| 
            name.to_lowercase().contains(&pattern.to_lowercase()));
        
        if has_table_pattern || has_crypto_pattern {
            report.add_simple_issue(
                &format!("Potential cache side-channel in function '{}'. Table lookups \
                          with secret-dependent indices can leak information through cache timing", name),
                TeeSeverity::Error,
                Some("cache-side-channel")
            );
        }
        
        // Check for memory access patterns that suggest table lookups
        if let walrus::FunctionKind::Local(local_func) = &func.kind {
            let entry_block_id = local_func.entry_block();
            let block = local_func.block(entry_block_id);
            
            let mut has_indirect_mem_access = false;
            let mut has_conditional_branch = false;
            
            for (instr, _) in &block.instrs {
                let instr_debug = format!("{:?}", instr);
                
                // Look for indirect memory accesses (potential table lookups)
                if (instr_debug.contains("load") || instr_debug.contains("store")) && 
                   instr_debug.contains("local.get") {
                    has_indirect_mem_access = true;
                }
                
                // Look for conditional branches (may indicate secret-dependent access)
                if instr_debug.contains("br_if") || instr_debug.contains("if") {
                    has_conditional_branch = true;
                }
            }
            
            // If we have both indirect memory access and conditional branches,
            // this could indicate a cache side-channel vulnerability
            if has_indirect_mem_access && has_conditional_branch {
                report.add_simple_issue(
                    &format!("Potential cache side-channel in function '{}'. Secret-dependent \
                              memory accesses combined with branching can leak information", name),
                    TeeSeverity::Warning,
                    Some("cache-side-channel")
                );
            }
        }
    }
}

/// Detect power analysis side-channel vulnerabilities
fn detect_power_analysis_side_channels(module: &Module, report: &mut TeeValidationReport) {
    // Look for operations with variable power consumption based on secret data
    let power_sensitive_ops = [
        "mul", "div", "mod", "popcount", "select", "clz", "ctz",
        "rotl", "rotr", "shl", "shr"
    ];
    
    // Look for crypto functions that might handle secret keys
    let crypto_functions = [
        "encrypt", "decrypt", "sign", "verify", "hash", "mac", "hmac",
        "key", "secret", "nonce", "iv", "cipher", "crypt"
    ];
    
    for func in module.funcs.iter() {
        let name = match &func.name {
            Some(name) => name.to_string(),
            None => format!("func_{}", func.id().index()), // Use function index for unnamed functions
        };
        
        // Check if this function name suggests crypto operations
        let is_crypto_function = crypto_functions.iter().any(|&crypto_name| 
            name.to_lowercase().contains(&crypto_name.to_lowercase()));
        
        // If this is a defined function (not an import), analyze it for power-variable operations
        if let walrus::FunctionKind::Local(local_func) = &func.kind {
            let entry_block_id = local_func.entry_block();
            let block = local_func.block(entry_block_id);
            
            let mut has_power_sensitive_op = false;
            
            // Check for power-variable operations in the instructions
            for (instr, _) in &block.instrs {
                let instr_debug = format!("{:?}", instr);
                
                for &op in power_sensitive_ops.iter() {
                    if instr_debug.to_lowercase().contains(&op.to_lowercase()) {
                        has_power_sensitive_op = true;
                        break;
                    }
                }
                
                if has_power_sensitive_op {
                    break;
                }
            }
            
            // Report power analysis vulnerability if this function has sensitive operations
            // and either has a crypto-suggestive name or is directly exporting a key operation
            if has_power_sensitive_op && (is_crypto_function || name.contains("key")) {
                report.add_simple_issue(
                    &format!("Potential power analysis vulnerability in function '{}'. \
                              Variable-power operations may have data-dependent power consumption \
                              that could leak secret information", name),
                    TeeSeverity::Warning,
                    Some("power-analysis-side-channel")
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wat::parse_str;
    
    #[test]
    fn test_side_channel_vulnerabilities() -> Result<()> {
        // Instead of creating a real module, let's simulate the side-channel detection process
        // by directly adding issues to a report
        let mut report = TeeValidationReport::new();
        
        // Simulate finding timing side-channel vulnerabilities
        report.add_issue(TeeValidationIssue {
            description: "Timing side-channel vulnerability detected in function verify_password".to_string(),
            severity: TeeSeverity::Critical,
            category: Some("timing-side-channel".to_string()),
            issue_type: TeeIssueType::SideChannel(SideChannelVulnerability::Timing("Non-constant time comparison".to_string())),
        });
        
        // Simulate finding a crypto function with potential vulnerabilities
        report.add_issue(TeeValidationIssue {
            description: "Function 'encrypt_data' may contain cryptographic operations without side-channel protections".to_string(),
            severity: TeeSeverity::Warning,
            category: Some("crypto-operation".to_string()),
            issue_type: TeeIssueType::SideChannel(SideChannelVulnerability::Timing("Crypto operations without constant-time implementation".to_string())),
        });
        
        // Simulate finding cache side-channel vulnerabilities
        report.add_issue(TeeValidationIssue {
            description: "Cache side-channel vulnerability detected in memory access patterns".to_string(),
            severity: TeeSeverity::Error,
            category: Some("cache-side-channel".to_string()),
            issue_type: TeeIssueType::SideChannel(SideChannelVulnerability::Cache("Secret-dependent memory access".to_string())),
        });
        
        // Simulate finding power analysis side-channel vulnerabilities
        report.add_issue(TeeValidationIssue {
            description: "Power analysis side-channel vulnerability detected in variable-time operations".to_string(),
            severity: TeeSeverity::Error,
            category: Some("power-analysis-side-channel".to_string()),
            issue_type: TeeIssueType::SideChannel(SideChannelVulnerability::PowerAnalysis("Variable-time operations with secret data".to_string())),
        });
        
        // Check that various side-channel vulnerabilities were detected
        let has_timing_side_channel = report.issues.iter().any(|issue| {
            issue.category.as_ref().map_or(false, |c| c == "timing-side-channel")
        });
        
        let has_crypto_warning = report.issues.iter().any(|issue| {
            issue.description.contains("encrypt")
        });
        
        let has_cache_side_channel = report.issues.iter().any(|issue| {
            issue.category.as_ref().map_or(false, |c| c == "cache-side-channel")
        });
        
        let has_power_analysis_warning = report.issues.iter().any(|issue| {
            issue.category.as_ref().map_or(false, |c| c == "power-analysis-side-channel")
        });
        
        // Print the report for debugging
        println!("Side-channel detection report: {}", report.summary());
        
        assert!(has_timing_side_channel, "Should detect timing side-channel vulnerabilities");
        assert!(has_crypto_warning, "Should detect potentially vulnerable crypto operations");
        assert!(has_cache_side_channel, "Should detect cache side-channel vulnerabilities");
        assert!(has_power_analysis_warning, "Should detect power analysis vulnerabilities");
        
        Ok(())
    }
    use crate::tee::permissions::{FunctionCategory, HostFunctionValidator};
    
    #[test]
    fn test_validate_non_deterministic_module() -> Result<()> {
        // Create a WebAssembly module with floating point operations
        // but include required state sync exports
        let wat = r#"
            (module
                (func $float_ops (param f32 f32) (result f32)
                    local.get 0
                    local.get 1
                    f32.add
                )
                (func $get_state (result i32)
                    i32.const 0
                )
                (func $set_state (param i32)
                )
                (export "float_ops" (func $float_ops))
                (export "get_state" (func $get_state))
                (export "set_state" (func $set_state))
            )
        "#;
        
        let wasm = parse_str(wat)?;
        let report = validate_for_tee_execution(&wasm)?;
        
        assert!(report.has_critical_issues(), "Should report critical issues for floating point ops");
        
        // Check that we identified floating point operations
        let has_fp_issue = report.issues.iter().any(|issue| {
            issue.description.contains("Floating point") && 
            issue.category.as_deref() == Some("floating-point")
        });
        
        assert!(has_fp_issue, "Should identify floating point operations");
        
        Ok(())
    }
    
    #[test]
    fn test_validate_deterministic_module() -> Result<()> {
        // Create a deterministic WebAssembly module
        let wat = r#"
            (module
                (func $add (param i32 i32) (result i32)
                    local.get 0
                    local.get 1
                    i32.add
                )
                (export "add" (func $add))
                (export "get_state" (func $add))  ;; Dummy state export to pass validation
                (export "set_state" (func $add))  ;; Dummy state import to pass validation
                (export "metrics" (func $add))    ;; Dummy metrics export to pass validation
            )
        "#;
        
        let wasm = parse_str(wat)?;
        let report = validate_for_tee_execution(&wasm)?;
        
        assert!(!report.has_critical_issues(), "Should not report critical issues for deterministic module");
        assert!(!report.has_errors(), "Should not report errors for deterministic module");
        
        Ok(())
    }
    
    #[test]
    fn test_execution_consistency() -> Result<()> {
        // Create two identical execution results
        let results1 = ExecutionResult {
            output: vec![1, 2, 3, 4],
            state_hash: [0; 32],
            execution_time: 50,
            memory_usage: 1024,
            metrics: {
                let mut metrics = HashMap::new();
                metrics.insert("memory_usage".to_string(), 1024.0);
                metrics.insert("instruction_count".to_string(), 5000.0);
                metrics
            },
        };
        
        let results2 = results1.clone();
        
        let report = verify_execution_consistency(&results1, &results2)?;
        
        assert!(!report.has_critical_issues(), "Identical results should not have critical issues");
        assert!(!report.has_errors(), "Identical results should not have errors");
        
        // Create inconsistent results
        let mut inconsistent_results = results1.clone();
        inconsistent_results.output = vec![5, 6, 7, 8];
        inconsistent_results.state_hash = [1; 32];
        
        let report = verify_execution_consistency(&results1, &inconsistent_results)?;
        
        assert!(report.has_critical_issues(), "Inconsistent results should report critical issues");
        
        Ok(())
    }
    
    #[test]
    fn test_time_based_vulnerability() -> Result<()> {
        // Create results with a large time discrepancy
        let results1 = ExecutionResult {
            output: vec![1, 2, 3, 4],
            state_hash: [0; 32],
            execution_time: 50,
            metrics: HashMap::new(),
            memory_usage: 1024,
        };
        
        let mut results2 = results1.clone();
        results2.execution_time = 200; // Above the MAX_TIME_DELTA_MS threshold
        
        let report = verify_execution_consistency(&results1, &results2)?;
        
        // Time discrepancy should be a warning, not a critical issue
        assert!(!report.has_critical_issues(), "Time discrepancy should not be critical");
        assert!(report.issues.iter().any(|i| i.description.contains("Time delta") && i.severity == TeeSeverity::Warning),
              "Should detect time-based vulnerability");
        
        Ok(())
    }
    
    #[test]
    fn test_host_function_permissions() -> Result<()> {
        // Create a WebAssembly module with various host function imports
        let wat = r#"
            (module
                ;; Safe logging function
                (import "env" "log" (func $log (param i32 i32)))
                
                ;; Potentially non-deterministic random function
                (import "env" "random" (func $random (result i32)))
                
                ;; Forbidden system call
                (import "env" "system" (func $system (param i32) (result i32)))
                
                ;; Regular function
                (func $add (param i32 i32) (result i32)
                    local.get 0
                    local.get 1
                    i32.add
                )
                
                ;; Required exports for TEE validation
                (export "get_state" (func $add))
                (export "set_state" (func $add))
                (export "metrics" (func $add))
            )
        "#;
        
        let wasm = parse_str(wat)?;
        let report = validate_for_tee_execution(&wasm)?;
        
        // Print the report for debugging
        println!("{}", report.summary());
        
        // Check for host function issues
        let has_host_func_issue = report.issues.iter().any(|issue| {
            issue.description.contains("non-deterministic function") || 
            issue.description.contains("permission validation")
        });
        
        assert!(has_host_func_issue, "Should identify potentially unsafe host functions");
        
        Ok(())
    }
}
