/// Solady Library Vulnerability Detector
/// Detects issues specific to Solady gas-optimized libraries
/// Critical for: Solady adoption (alternative to OpenZeppelin)

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoladyVulnerability {
    pub vulnerability_type: SoladyIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SoladyIssueType {
    AssemblyOptimizationEdgeCase, // Assembly optimization bug
    FixedPointMathPrecision,       // FixedPointMathLib precision loss
    SafeTransferLibEdgeCase,       // SafeTransferLib edge case
    PackedStructManipulation,      // Packed struct exploit
    LibBitLowLevelBug,             // LibBit bit operation bug
}

pub struct SoladyLibraryDetector {
    bytecode: Vec<u8>,
}

impl SoladyLibraryDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SoladyVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.uses_solady() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_assembly_issues());
        vulnerabilities.extend(self.detect_math_precision());

        vulnerabilities
    }

    fn detect_assembly_issues(&self) -> Vec<SoladyVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.has_unchecked_assembly(i) {
                vulnerabilities.push(SoladyVulnerability {
                    vulnerability_type: SoladyIssueType::AssemblyOptimizationEdgeCase,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.70,
                    description: "Solady assembly optimization without edge case handling".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Uses Solady assembly-optimized function\n\
                        2. Edge case not handled in optimization\n\
                        3. Unexpected input triggers bug\n\
                        4. State corruption or loss of funds\n\n\
                        Fix: Validate inputs before assembly calls",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn detect_math_precision(&self) -> Vec<SoladyVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.uses_fixed_point_math(i) && !self.checks_precision(i) {
                vulnerabilities.push(SoladyVulnerability {
                    vulnerability_type: SoladyIssueType::FixedPointMathPrecision,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.65,
                    description: "Solady FixedPointMathLib used without precision checks".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Uses Solady FixedPointMathLib\n\
                        2. No precision loss validation\n\
                        3. Small rounding errors accumulate\n\
                        4. Economic exploit via precision loss\n\n\
                        Fix: Validate precision requirements",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn uses_solady(&self) -> bool {
        // Heuristic: Look for Solady-specific patterns
        // Solady uses heavy inline assembly
        let inline_asm_count = self.bytecode.iter().filter(|&&b| b == 0xFE).count(); // INVALID (asm marker)
        inline_asm_count > 5
    }

    fn has_unchecked_assembly(&self, pos: usize) -> bool {
        // Assembly blocks without prior validation
        pos + 10 < self.bytecode.len() && self.bytecode[pos] == 0xFE
    }

    fn uses_fixed_point_math(&self, pos: usize) -> bool {
        // MUL followed by DIV (fixed point)
        pos + 5 < self.bytecode.len() &&
        self.bytecode[pos] == 0x02 && // MUL
        self.bytecode[pos+3] == 0x04 // DIV
    }

    fn checks_precision(&self, pos: usize) -> bool {
        // Look for remainder check
        for i in pos..pos.saturating_add(20).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x06 { // MOD
                return true;
            }
        }
        false
    }
}
