use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLeakage {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
    pub log_topics: usize,
}

pub struct EventEmissionInformationLeakageDetector {
    bytecode: Vec<u8>,
}

impl EventEmissionInformationLeakageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<EventLeakage> {
        let mut vulnerabilities = Vec::new();

        // Detect all LOG opcodes (potential information leakage)
        vulnerabilities.extend(self.detect_log_emissions());
        
        // Detect conditional LOG emissions (execution path leakage)
        vulnerabilities.extend(self.detect_conditional_logs());
        
        // Detect LOG after SLOAD (potentially leaking private storage)
        vulnerabilities.extend(self.detect_storage_to_event_leak());

        vulnerabilities
    }

    fn detect_log_emissions(&self) -> Vec<EventLeakage> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // LOG0 to LOG4 opcodes (0xA0 - 0xA4)
            if (0xA0..=0xA4).contains(&opcode) {
                let topic_count = (opcode - 0xA0) as usize;
                
                vulns.push(EventLeakage {
                    pc,
                    vulnerability_type: "EventEmission".to_string(),
                    description: format!(
                        "LOG{} event emission at PC {}. Events are publicly visible on blockchain. \
                        Ensure no sensitive data (private keys, passwords, user secrets, internal states) \
                        is included in event parameters. Events should only contain public information \
                        or cryptographic commitments to private data.",
                        topic_count, pc
                    ),
                    confidence: 0.60,
                    log_topics: topic_count,
                });
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_conditional_logs(&self) -> Vec<EventLeakage> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for LOG opcodes preceded by JUMPI (conditional emission)
            if (0xA0..=0xA4).contains(&opcode) {
                let start = if pc > 30 { pc - 30 } else { 0 };
                let has_conditional = self.bytecode[start..pc].iter().any(|&b| b == 0x57); // JUMPI
                
                if has_conditional {
                    let topic_count = (opcode - 0xA0) as usize;
                    vulns.push(EventLeakage {
                        pc,
                        vulnerability_type: "ConditionalEventEmission".to_string(),
                        description: format!(
                            "Conditional LOG{} emission at PC {}. Event emission depends on execution path. \
                            Observers can infer which code branch was taken by monitoring event logs, \
                            potentially revealing sensitive business logic, access control decisions, \
                            or user-specific behavior patterns.",
                            topic_count, pc
                        ),
                        confidence: 0.80,
                        log_topics: topic_count,
                    });
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_storage_to_event_leak(&self) -> Vec<EventLeakage> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for SLOAD followed by LOG (private storage → public event)
            if opcode == 0x54 { // SLOAD
                let window_end = (pc + 40).min(self.bytecode.len());
                for check_pc in (pc + 1)..window_end {
                    let check_op = self.bytecode[check_pc];
                    if (0xA0..=0xA4).contains(&check_op) {
                        let topic_count = (check_op - 0xA0) as usize;
                        vulns.push(EventLeakage {
                            pc,
                            vulnerability_type: "StorageToEventLeak".to_string(),
                            description: format!(
                                "SLOAD at PC {} followed by LOG{} at PC {}. Private storage data \
                                may be emitted in public event. Storage often contains sensitive information \
                                (user balances, permissions, private states) that should not be publicly \
                                broadcast. Consider using cryptographic commitments or hashes in events.",
                                pc, topic_count, check_pc
                            ),
                            confidence: 0.85,
                            log_topics: topic_count,
                        });
                        break;
                    }
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }
}
