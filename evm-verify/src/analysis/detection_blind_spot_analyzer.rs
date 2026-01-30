/// Detection Blind Spot Analyzer
/// Identifies areas of bytecode that no detector examines
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone)]
pub struct DetectionBlindSpotAnalyzer {
    bytecode: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BlindSpot {
    pub start: usize,
    pub end: usize,
    pub reason: String,
    pub risk_level: SecuritySeverity,
}

impl DetectionBlindSpotAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn find_blind_spots(&self, detector_coverage: &[(String, Vec<usize>)]) -> Vec<BlindSpot> {
        let mut blind_spots = Vec::new();
        
        // Create coverage map
        let mut covered = vec![false; self.bytecode.len()];
        for (_, locations) in detector_coverage {
            for &loc in locations {
                if loc < covered.len() {
                    covered[loc] = true;
                }
            }
        }

        // Find uncovered regions
        let mut start = None;
        for (i, &is_covered) in covered.iter().enumerate() {
            if !is_covered && start.is_none() {
                start = Some(i);
            } else if is_covered && start.is_some() {
                blind_spots.push(BlindSpot {
                    start: start.unwrap(),
                    end: i,
                    reason: "No detector examines this region".to_string(),
                    risk_level: SecuritySeverity::Medium,
                });
                start = None;
            }
        }

        blind_spots
    }

    pub fn analyze_uncovered_opcodes(&self) -> Vec<(usize, u8, String)> {
        let mut uncovered = Vec::new();
        
        // Find potentially dangerous opcodes that might be missed
        for (i, &opcode) in self.bytecode.iter().enumerate() {
            if self.is_dangerous_opcode(opcode) {
                uncovered.push((i, opcode, "Dangerous opcode in blind spot".to_string()));
            }
        }

        uncovered
    }

    fn is_dangerous_opcode(&self, opcode: u8) -> bool {
        matches!(opcode, 
            0xf0 | // CREATE
            0xf5 | // CREATE2
            0xfa | // STATICCALL
            0xff   // SELFDESTRUCT
        )
    }

    pub fn suggest_new_detectors(&self, blind_spots: &[BlindSpot]) -> Vec<String> {
        let mut suggestions = Vec::new();

        for spot in blind_spots {
            if spot.end - spot.start > 100 {
                suggestions.push(format!(
                    "Large uncovered region at {}-{}: Consider detector for this pattern",
                    spot.start, spot.end
                ));
            }
        }

        suggestions
    }
}
