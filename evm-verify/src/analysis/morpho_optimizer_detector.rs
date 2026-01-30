use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MorphoOptimizerVulnerability {
    P2PMatchingExploit,
    SupplyQueueManipulation,
    BorrowQueueBypass,
    MatchingEngineGaming,
    PoolOptimizationBypass,
    LiquidityFragmentationRisk,
    RateSpreadManipulation,
    SupplyCapBypass,
    PromotionFlowExploit,
    PositionManagerAccessControl,
}

pub struct MorphoOptimizerDetector {
    bytecode: Vec<u8>,
}

impl MorphoOptimizerDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MorphoOptimizerVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_matching_validation() {
            vulnerabilities.push(MorphoOptimizerVulnerability::MatchingEngineGaming);
        }
        vulnerabilities
    }

    fn has_matching_validation(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x54 && w[1] == 0x11)
    }
}
