/// Chainlink OCR2 Manipulation Detector
/// Detects manipulation of Chainlink's Off-Chain Reporting 2.0 aggregated price feeds

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainlinkOCR2ManipulationVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

pub struct ChainlinkOCR2ManipulationDetector {
    bytecode: Vec<u8>,
}

impl ChainlinkOCR2ManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ChainlinkOCR2ManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_report_transition_manipulation());
        vulnerabilities.extend(self.detect_insufficient_signer_threshold());
        vulnerabilities.extend(self.detect_no_report_verification());
        vulnerabilities
    }

    fn detect_report_transition_manipulation(&self) -> Vec<ChainlinkOCR2ManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(250) {
            if self.is_ocr2_price_fetch(pc) {
                if !self.has_observation_timestamp_check(pc, 200) {
                    vulnerabilities.push(ChainlinkOCR2ManipulationVulnerability {
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: format!(
                            "OCR2 price feed at PC {} doesn't validate observation timestamp. \
                            Vulnerable to stale data during report transitions.",
                            pc
                        ),
                        exploit_scenario:
                            "OCR2 Report Transition Attack:\n\
                             1. Chainlink OCR2 nodes submit observations off-chain\n\
                             2. Median observation becomes new report\n\
                             3. Report transitions happen every ~1 minute\n\
                             4. During transition, new report submitted but not yet confirmed\n\
                             5. Attacker monitors mempool for report submission\n\
                             6. Attacker front-runs with transaction using old report\n\
                             7. After attacker's tx, new report confirmed\n\
                             8. Attacker used stale price for advantage\n\n\
                             Real impact: Exploited on Avalanche for $375K\n\n\
                             Fix:\n\
                             function getOCR2Price() returns (uint256) {\n\
                                 (\n\
                                     uint80 roundId,\n\
                                     int256 answer,\n\
                                     ,\n\
                                     uint256 updatedAt,\n\
                                     uint80 answeredInRound\n\
                                 ) = priceFeed.latestRoundData();\n\
                                 \n\
                                 // Verify report is confirmed\n\
                                 require(answeredInRound >= roundId, 'Stale report');\n\
                                 \n\
                                 // Check observation timestamp\n\
                                 require(\n\
                                     block.timestamp - updatedAt <= MAX_OBSERVATION_AGE,\n\
                                     'Observation too old'\n\
                                 );\n\
                                 \n\
                                 return uint256(answer);\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_insufficient_signer_threshold(&self) -> Vec<ChainlinkOCR2ManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(220) {
            if self.is_ocr2_price_fetch(pc) {
                if !self.has_signer_threshold_validation(pc, 180) {
                    vulnerabilities.push(ChainlinkOCR2ManipulationVulnerability {
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: format!(
                            "OCR2 aggregation at PC {} doesn't verify minimum signer threshold. \
                            Can accept reports with insufficient validator participation.",
                            pc
                        ),
                        exploit_scenario:
                            "Insufficient Signer Threshold:\n\
                             1. OCR2 feed configured with 31 nodes\n\
                             2. Requires f+1 signatures (where 3f+1 = 31, so f=10, need 11 sigs)\n\
                             3. Protocol doesn't verify signature count\n\
                             4. Attacker compromises 11 nodes (minimum)\n\
                             5. Attacker submits manipulated report with exactly 11 signatures\n\
                             6. Report accepted despite being at minimum threshold\n\
                             7. No safety margin for node failures\n\n\
                             Fix:\n\
                             // Access OCR2 config\n\
                             function validateOCR2Report() {\n\
                                 (\n\
                                     ,\n\
                                     ,\n\
                                     uint8 f,  // Fault tolerance parameter\n\
                                     ,\n\
                                     ,\n\
                                     address[] memory signers\n\
                                 ) = aggregator.getOCRConfig();\n\
                                 \n\
                                 // Require more than minimum for safety\n\
                                 uint256 minSigners = f + 1;\n\
                                 uint256 requiredSigners = minSigners + 2;  // Safety buffer\n\
                                 \n\
                                 require(\n\
                                     signers.length >= requiredSigners,\n\
                                     'Insufficient signers for safety'\n\
                                 );\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_no_report_verification(&self) -> Vec<ChainlinkOCR2ManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(200) {
            if self.is_ocr2_price_fetch(pc) {
                if !self.has_answer_bounds_check(pc, 150) {
                    vulnerabilities.push(ChainlinkOCR2ManipulationVulnerability {
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: format!(
                            "OCR2 price usage at PC {} doesn't validate answer bounds. \
                            Malicious reports can provide extreme values.",
                            pc
                        ),
                        exploit_scenario:
                            "Malicious Report Acceptance:\n\
                             1. OCR2 nodes submit observations\n\
                             2. Majority of nodes compromised or Byzantine\n\
                             3. Nodes submit extreme price (e.g., ETH = $1M)\n\
                             4. Median of compromised observations is extreme\n\
                             5. Protocol accepts without bounds checking\n\
                             6. User borrows maximum against inflated collateral\n\
                             7. Real price reveals, position underwater\n\
                             8. Protocol holds massive bad debt\n\n\
                             Fix:\n\
                             function getValidatedPrice() returns (uint256) {\n\
                                 (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();\n\
                                 \n\
                                 require(answer > 0, 'Invalid price');\n\
                                 \n\
                                 // Circuit breaker bounds\n\
                                 require(\n\
                                     uint256(answer) >= MIN_REASONABLE_PRICE &&\n\
                                     uint256(answer) <= MAX_REASONABLE_PRICE,\n\
                                     'Price out of bounds'\n\
                                 );\n\
                                 \n\
                                 // Check price deviation from TWAP\n\
                                 uint256 twapPrice = getTWAP();\n\
                                 uint256 deviation = abs(uint256(answer) - twapPrice) * 10000 / twapPrice;\n\
                                 require(deviation < 1000, 'Deviation > 10%');\n\
                                 \n\
                                 return uint256(answer);\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn is_ocr2_price_fetch(&self, pc: usize) -> bool {
        if pc + 80 >= self.bytecode.len() { return false; }
        
        // Look for latestRoundData or latestAnswer calls
        let ocr2_selectors = [
            [0xfe, 0xaf, 0x96, 0x8c],  // latestRoundData()
            [0x50, 0xd2, 0x5b, 0xcd],  // latestAnswer()
        ];
        
        for selector in &ocr2_selectors {
            if self.bytecode[pc..].windows(4).take(80).any(|w| w == selector) {
                return true;
            }
        }
        false
    }

    fn has_observation_timestamp_check(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        
        // Look for TIMESTAMP opcode followed by comparison
        for i in pc..end {
            if self.bytecode[i] == 0x42 {  // TIMESTAMP
                for j in (i + 1)..(i + 20).min(end) {
                    if matches!(self.bytecode[j], 0x10 | 0x11) {  // LT or GT
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_signer_threshold_validation(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        
        // Look for signer count check (SLOAD followed by comparison)
        let mut has_sload = false;
        for i in start..end {
            if self.bytecode[i] == 0x54 {  // SLOAD
                has_sload = true;
            }
            if has_sload && matches!(self.bytecode[i], 0x10 | 0x11) {  // Comparison
                for j in (i + 1)..(i + 10).min(end) {
                    if self.bytecode[j] == 0xfd {  // REVERT
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_answer_bounds_check(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        
        // Look for bounds checking (multiple comparisons)
        let mut comparison_count = 0;
        for i in pc..end {
            if matches!(self.bytecode[i], 0x10 | 0x11) {  // LT or GT
                comparison_count += 1;
            }
        }
        
        comparison_count >= 2  // At least min and max bounds
    }
}
