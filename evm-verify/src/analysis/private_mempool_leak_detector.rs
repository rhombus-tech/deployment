/// Private Mempool Leak Detector
use crate::bytecode::SecurityFinding;

pub struct PrivateMempoolLeakDetector {
    bytecode: Vec<u8>,
}

impl PrivateMempoolLeakDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Private mempool information leakage at PC {}", location),
                pc: location,
                confidence: 0.83,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(65) {
            if self.check_mempool_leak(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_mempool_leak(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for private transaction info being leaked
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // submitTransaction, executePrivate, flashbotsBundle selectors
            if matches!(self.bytecode[pos+1], 0x1f | 0x4e | 0x7d | 0xa3) {
                let mut emits_transaction_details = false;
                let mut stores_unencrypted_data = false;
                let mut reveals_order_info = false;
                let mut leaks_timing_info = false;
                
                if pos + 60 < self.bytecode.len() {
                    // Check for LOG events that emit private transaction details
                    for j in (pos + 5)..(pos + 35).min(self.bytecode.len()) {
                        if matches!(self.bytecode[j], 0xa0 | 0xa1 | 0xa2 | 0xa3 | 0xa4) { // LOG0-LOG4
                            emits_transaction_details = true;
                        }
                    }
                    
                    // Check for storing unencrypted sensitive data
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // SSTORE without encryption
                            stores_unencrypted_data = true;
                        }
                    }
                    
                    // Check for revealing order book information
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j + 3 < self.bytecode.len() { // SLOAD
                            // If publicly accessible, leaks order info
                            if self.bytecode[j + 2] == 0x51 { // MLOAD (returning data)
                                reveals_order_info = true;
                            }
                        }
                    }
                    
                    // Check for timing information leakage
                    for j in (pos + 5)..(pos + 60).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 { // TIMESTAMP in events
                            leaks_timing_info = true;
                        }
                    }
                }
                
                // Vulnerable if private mempool info is leaked via:
                // 1. Events exposing transaction details
                // 2. Unencrypted storage of sensitive data
                // 3. Public access to order information
                // 4. Timing information revealing order flow
                return emits_transaction_details || stores_unencrypted_data || reveals_order_info || leaks_timing_info;
            }
        }
        false
    }
}
