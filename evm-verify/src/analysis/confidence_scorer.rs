/// Confidence Scoring System
/// Adjusts vulnerability confidence based on multiple factors

pub struct ConfidenceScorer;

impl ConfidenceScorer {
    /// Calculate final confidence score
    pub fn score(
        base_confidence: f32,
        has_protection: bool,
        protection_strength: f32,
        historical_false_positive_rate: f32,
        code_quality_signals: &CodeQualitySignals,
    ) -> f32 {
        let mut confidence = base_confidence;
        
        // 1. Protection mechanisms
        if has_protection {
            confidence *= (1.0 - protection_strength);
        }
        
        // 2. Historical accuracy
        // If this detector has 30% false positive rate, reduce confidence
        confidence *= (1.0 - historical_false_positive_rate);
        
        // 3. Code quality signals
        if code_quality_signals.uses_safe_libraries {
            confidence *= 0.7; // 30% reduction
        }
        
        if code_quality_signals.recent_audit {
            confidence *= 0.5; // 50% reduction - audited code less likely vulnerable
        }
        
        if code_quality_signals.high_test_coverage {
            confidence *= 0.8; // 20% reduction
        }
        
        // 4. Compiler version (Solidity 0.8+ has built-in protections)
        if code_quality_signals.solidity_version >= 8 {
            confidence *= 0.6; // 40% reduction for integer overflows
        }
        
        confidence.clamp(0.0, 1.0)
    }
    
    /// Determine if finding should be reported
    pub fn should_report(confidence: f32, severity: &str) -> bool {
        match severity {
            "Critical" => confidence > 0.3, // Low threshold for critical
            "High" => confidence > 0.5,
            "Medium" => confidence > 0.7,
            "Low" => confidence > 0.85,
            _ => confidence > 0.9,
        }
    }
}

pub struct CodeQualitySignals {
    pub uses_safe_libraries: bool,     // OpenZeppelin, etc.
    pub recent_audit: bool,             // Audited in last 6 months
    pub high_test_coverage: bool,       // >80% coverage
    pub solidity_version: u8,           // 6, 7, 8, etc.
    pub deployment_age_days: u32,       // How long deployed
    pub tvl_usd: f64,                   // Total value locked
}

impl CodeQualitySignals {
    pub fn from_bytecode(bytecode: &[u8]) -> Self {
        Self {
            uses_safe_libraries: Self::detect_safe_libraries(bytecode),
            recent_audit: false, // Would need external data
            high_test_coverage: false, // Would need external data
            solidity_version: Self::detect_solidity_version(bytecode),
            deployment_age_days: 0, // Would query chain
            tvl_usd: 0.0, // Would query DeFi protocols
        }
    }
    
    fn detect_safe_libraries(bytecode: &[u8]) -> bool {
        // Look for OpenZeppelin patterns
        let oz_patterns = [
            vec![0x54, 0x60, 0x02, 0x14], // ReentrancyGuard
            vec![0x73, 0x9f], // SafeERC20 signature
        ];
        
        oz_patterns.iter().any(|pattern| {
            bytecode.windows(pattern.len()).any(|w| w == &pattern[..])
        })
    }
    
    fn detect_solidity_version(bytecode: &[u8]) -> u8 {
        // Heuristic: Solidity 0.8+ has specific overflow check patterns
        let has_0_8_overflow = bytecode.windows(4)
            .any(|w| matches!(w, [0x01, 0x10, 0x15, 0x57])); // ADD with overflow check
        
        if has_0_8_overflow {
            8
        } else {
            7 // Assume 0.7 or earlier
        }
    }
}
