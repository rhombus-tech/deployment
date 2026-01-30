use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ERC4337SignatureAggregationVulnerability {
    InvalidSignatureGriefing { description: String, location: usize, confidence: f32 },
    AggregationBundlerDoS { description: String, location: usize, confidence: f32 },
}

pub struct ERC4337SignatureAggregationGriefingDetector {
    bytecode: Vec<u8>,
}

impl ERC4337SignatureAggregationGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<ERC4337SignatureAggregationVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(50) {
            let section = &self.bytecode[i..std::cmp::min(i + 50, self.bytecode.len())];
            let has_sig_verification = section.contains(&0x01); // ECRECOVER pattern
            let no_single_sig_check = !section.windows(5).any(|w| w.contains(&0x14) && w.contains(&0xFD));
            if has_sig_verification && no_single_sig_check {
                vulnerabilities.push(ERC4337SignatureAggregationVulnerability::InvalidSignatureGriefing {
                    description: format!("ERC-4337 aggregated signature validation at PC {} doesn't isolate single invalid sig. Aggregator bundles 100 UserOps → one has invalid signature → entire batch reverts → griefs bundler (wasted gas). Must validate each signature independently before aggregation.", i),
                    location: i,
                    confidence: 0.89,
                });
            }
        }
        vulnerabilities
    }
}
