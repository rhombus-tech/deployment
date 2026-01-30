use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainlinkL2SequencerVulnerability {
    MissingSequencerUptimeCheck { description: String, location: usize, confidence: f32 },
    StaleGracePeriodInsufficient { description: String, location: usize, confidence: f32 },
}

pub struct ChainlinkL2SequencerUptimeFeedDetector {
    bytecode: Vec<u8>,
}

impl ChainlinkL2SequencerUptimeFeedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<ChainlinkL2SequencerVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // L2 sequencer downtime = stale Chainlink prices ($100M+ at risk)
        for i in 0..self.bytecode.len().saturating_sub(100) {
            let section = &self.bytecode[i..std::cmp::min(i + 100, self.bytecode.len())];
            
            // Pattern: Chainlink price feed read without sequencer uptime check
            let has_chainlink_read = section.windows(4).any(|w| {
                w[0] == 0x63 && (w[1] == 0x50 || w[1] == 0xfe) // latestRoundData() or getRoundData()
            });
            
            // Check for sequencer uptime feed (specific address pattern on L2s)
            let has_sequencer_check = section.windows(25).any(|w| {
                w.contains(&0xFA) && // STATICCALL to sequencer feed
                w.contains(&0x15) && // ISZERO (check if answer == 0)
                w.contains(&0x57)    // JUMPI (revert if down)
            });
            
            if has_chainlink_read && !has_sequencer_check {
                vulnerabilities.push(ChainlinkL2SequencerVulnerability::MissingSequencerUptimeCheck {
                    description: format!("Chainlink L2 sequencer uptime not checked at PC {}. CRITICAL: On Arbitrum/Optimism/Base, if sequencer goes down, Chainlink oracles cannot update → stale prices. Attack: 1) Sequencer down for 1 hour, 2) ETH price moves 10%, 3) Attacker liquidates positions at stale price. Solution: Check Chainlink Sequencer Uptime Feed (address 0xFdB631F5EE196F0ed6FAa767959853A9F217697D on Arbitrum). Require: sequencerUptimeFeed.latestRoundData() returns (answer == 0 for up, 1 for down).", i),
                    location: i,
                    confidence: 0.92,
                });
            }
            
            // Grace period check
            if has_sequencer_check {
                let has_grace_period = section.windows(12).any(|w| {
                    w.contains(&0x42) && // TIMESTAMP
                    w.contains(&0x03) && // SUB (time since restart)
                    w.contains(&0x10)    // LT (grace period)
                });
                
                if !has_grace_period {
                    vulnerabilities.push(ChainlinkL2SequencerVulnerability::StaleGracePeriodInsufficient {
                        description: format!("Sequencer uptime checked but no grace period at PC {}. Best practice: After sequencer restarts, wait GRACE_PERIOD (e.g., 3600 seconds) before accepting prices. During downtime, price could have moved significantly. Wait for oracles to update post-restart.", i),
                        location: i,
                        confidence: 0.80,
                    });
                }
            }
        }
        
        vulnerabilities
    }
}
