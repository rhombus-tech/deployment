use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MulticallMsgValueReuseVulnerability {
    MsgValueInLoop { description: String, location: usize, confidence: f32 },
    MsgValueNotTracked { description: String, location: usize },
    ValueReusedAcrossCalls { description: String, location: usize },
}

pub struct MulticallMsgValueReuseDetector {
    bytecode: Vec<u8>,
}

impl MulticallMsgValueReuseDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MulticallMsgValueReuseVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_multicall_function(i, i + 100) {
                if self.uses_msg_value_in_loop(i, i + 100) {
                    vulnerabilities.push(MulticallMsgValueReuseVulnerability::MsgValueInLoop {
                        description: "msg.value used in multicall loop - can be reused across delegatecalls".to_string(),
                        location: i,
                        confidence: 0.90,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_multicall_function(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Multicall pattern: loop with DELEGATECALL
        let has_loop = self.bytecode[start..range_end].iter().any(|&b| b == 0x57);
        let has_delegatecall = self.bytecode[start..range_end].iter().any(|&b| b == 0xF4);
        
        has_loop && has_delegatecall
    }
    
    fn uses_msg_value_in_loop(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // CALLVALUE opcode in loop context
        self.bytecode[start..range_end].iter().any(|&b| b == 0x34)
    }
}
