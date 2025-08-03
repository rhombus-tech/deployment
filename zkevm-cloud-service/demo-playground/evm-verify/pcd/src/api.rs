// API Module for EVM-Verify PCD
// This module defines interfaces and types for PCD verification strategies

use serde::{Serialize, Deserialize};

/// Verification strategy for security checks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStrategy {
    /// Verify all security properties
    Comprehensive,
    /// Focus on high-risk vulnerabilities only
    HighRiskOnly,
    /// Focus on vulnerabilities related to financial safety
    FinancialSafety,
    /// Minimal verification for testing
    Minimal,
    /// Custom verification with specific checks
    Custom,
    /// Use Groth16 proving system
    Groth16,
    /// Use ZODA proving system
    ZODA,
}

impl Default for VerificationStrategy {
    fn default() -> Self {
        VerificationStrategy::Comprehensive
    }
}

// Add verification result types that can be used by clients
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub success: bool,
    pub strategy: VerificationStrategy,
    pub warnings: Vec<SecurityWarning>,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityWarning {
    pub warning_type: String,
    pub severity: String,
    pub description: String,
    pub message: String,
    pub line_number: Option<u32>,
    pub code_snippet: Option<String>,
    pub recommendation: Option<String>,
}
