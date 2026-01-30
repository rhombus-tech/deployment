use serde::{Deserialize, Serialize};

/// Delayed Inbox Censorship Detection (Arbitrum/Optimism L2)
/// 
/// Detects vulnerabilities in delayed inbox mechanisms:
/// 1. Forced transaction inclusion can be delayed indefinitely
/// 2. No timeout enforcement on delayed messages
/// 3. Sequencer can censor by delaying inbox processing
/// 4. Missing forced inclusion fallback
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DelayedInboxCensorshipVulnerability {
    /// Critical: No timeout on delayed message processing
    NoDelayedMessageTimeout {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// High: Sequencer can indefinitely delay forced transactions
    IndefiniteDelayPossible {
        description: String,
        location: usize,
    },
    /// High: Missing forced inclusion mechanism
    NoForcedInclusionFallback {
        description: String,
        location: usize,
    },
    /// Medium: Delayed inbox not validated
    DelayedInboxNotValidated {
        description: String,
        location: usize,
    },
}

pub struct DelayedInboxCensorshipDetector {
    bytecode: Vec<u8>,
}

impl DelayedInboxCensorshipDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DelayedInboxCensorshipVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Check for delayed inbox timeout
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if self.is_delayed_inbox_processing(i) {
                let has_timeout = self.has_timeout_enforcement(i, i + 150);
                
                if !has_timeout {
                    vulnerabilities.push(DelayedInboxCensorshipVulnerability::NoDelayedMessageTimeout {
                        description: "Delayed inbox messages can be processed without timeout limit".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
            }
        }
        
        // Pattern 2: Check for indefinite delay protection
        for i in 0..self.bytecode.len().saturating_sub(120) {
            if self.is_force_inclusion_function(i) {
                let can_be_delayed_indefinitely = self.can_delay_indefinitely(i, i + 120);
                
                if can_be_delayed_indefinitely {
                    vulnerabilities.push(DelayedInboxCensorshipVulnerability::IndefiniteDelayPossible {
                        description: "Forced inclusion can be delayed indefinitely by sequencer".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Pattern 3: Check for forced inclusion fallback
        let has_forced_inclusion = self.has_forced_inclusion_mechanism();
        
        if !has_forced_inclusion && self.is_l2_contract() {
            vulnerabilities.push(DelayedInboxCensorshipVulnerability::NoForcedInclusionFallback {
                description: "No forced inclusion mechanism for censorship resistance".to_string(),
                location: 0,
            });
        }
        
        // Pattern 4: Delayed inbox validation
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.uses_delayed_inbox(i) {
                let validates_inbox = self.validates_inbox_message(i, i + 100);
                
                if !validates_inbox {
                    vulnerabilities.push(DelayedInboxCensorshipVulnerability::DelayedInboxNotValidated {
                        description: "Delayed inbox message not properly validated".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_delayed_inbox_processing(&self, location: usize) -> bool {
        if location + 50 > self.bytecode.len() {
            return false;
        }
        
        // Look for delayed inbox contract calls
        // Arbitrum delayed inbox: 0x4Dbd4fc535Ac27206064B68FfCf827b0A60BAB3f
        self.bytecode[location..location + 50].windows(20).any(|w| {
            w.iter().any(|&b| b == 0xfa) && // STATICCALL
            w.iter().any(|&b| b == 0x73)    // PUSH20 (address)
        })
    }
    
    fn has_timeout_enforcement(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Timeout enforcement pattern:
        // 1. TIMESTAMP or NUMBER
        // 2. Comparison with delay threshold
        // 3. REVERT if timeout exceeded
        
        self.bytecode[start..range_end].windows(5).any(|w| {
            (w[0] == 0x42 || w[0] == 0x43) && // TIMESTAMP or NUMBER
            w.iter().skip(1).any(|&b| b == 0x10 || b == 0x11) && // LT or GT
            w.iter().any(|&b| b == 0xfd) // REVERT
        })
    }
    
    fn is_force_inclusion_function(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        // forceInclusion() or similar function
        // Common selectors for force include functions
        self.bytecode[location..location + 30].windows(4).any(|w| {
            w[0] == 0x63 && (w[1] == 0xf8 || w[1] == 0xe8)
        })
    }
    
    fn can_delay_indefinitely(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Check if there's a max delay check
        let has_max_delay = self.bytecode[start..range_end].windows(4).any(|w| {
            w[0] == 0x42 && // TIMESTAMP
            w[1] == 0x01 && // ADD (timestamp + max_delay)
            w[2] == 0x10    // LT (current < deadline)
        });
        
        !has_max_delay
    }
    
    fn has_forced_inclusion_mechanism(&self) -> bool {
        // Check for forceInclusion or enqueueL2 functions
        self.bytecode.windows(4).any(|w| {
            w[0] == 0x63 && (
                (w[1] == 0xf8 && w[2] == 0x0c) || // forceInclusion pattern
                (w[1] == 0xe8 && w[2] == 0x0e)    // enqueue pattern
            )
        })
    }
    
    fn is_l2_contract(&self) -> bool {
        // Detect L2-specific patterns
        // Check for L2-specific precompiles or bridge patterns
        self.bytecode.windows(20).any(|w| {
            w.iter().filter(|&&b| b == 0xfa).count() > 0 && // STATICCALL
            w.iter().filter(|&&b| b == 0x73).count() > 0    // Address push
        })
    }
    
    fn uses_delayed_inbox(&self, location: usize) -> bool {
        if location + 40 > self.bytecode.len() {
            return false;
        }
        
        // Check for delayed inbox interaction
        self.bytecode[location..location + 40].windows(4).any(|w| {
            w[0] == 0x63 && w[1] == 0x8d // Common inbox selector patterns
        })
    }
    
    fn validates_inbox_message(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Validation pattern:
        // 1. Check message sender
        // 2. Check message data
        // 3. Verify signature or proof
        
        let checks_sender = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0x33); // CALLER
        
        let checks_data = self.bytecode[start..range_end]
            .iter()
            .filter(|&&b| b == 0x35) // CALLDATALOAD
            .count() > 1;
        
        let has_verification = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0x14); // EQ (comparison)
        
        checks_sender && checks_data && has_verification
    }
}
