use serde::{Deserialize, Serialize};

/// Block Boundary Front-Running: Actions at block boundaries
/// Attack: First transaction in new block has special properties

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockBoundaryVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct BlockBoundaryFrontrunningDetector {
    bytecode: Vec<u8>,
}

impl BlockBoundaryFrontrunningDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<BlockBoundaryVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_block_boundary_dependency() {
            vulnerabilities.push(BlockBoundaryVulnerability {
                vulnerability_type: "Block Boundary State Change".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "State changes at block boundaries, front-runnable".to_string(),
                confidence: 0.85,
            });
        }
        vulnerabilities
    }
    fn has_block_boundary_dependency(&self) -> Option<usize> {
        // NUMBER check + state change
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x43 { // NUMBER (block number)
                for j in i+1..i+15.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 { // SSTORE (state change)
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
