use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TwapManipulationShortWindowVulnerability {
    WindowTooShort { description: String, location: usize, window_seconds: u64, confidence: f32 },
    SingleBlockTwap { description: String, location: usize },
    NoMinimumObservations { description: String, location: usize },
    ManipulableTimeWindow { description: String, location: usize },
}

pub struct TwapManipulationShortWindowDetector {
    bytecode: Vec<u8>,
}

impl TwapManipulationShortWindowDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TwapManipulationShortWindowVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_twap_calculation(i) {
                if let Some(window) = self.get_time_window(i, i + 100) {
                    // Standard: minimum 30 minutes for manipulation resistance
                    if window < 1800 {
                        vulnerabilities.push(TwapManipulationShortWindowVulnerability::WindowTooShort {
                            description: format!("TWAP window of {} seconds is too short - minimum 30 min recommended", window),
                            location: i,
                            window_seconds: window,
                            confidence: 0.90,
                        });
                    }
                }
                
                if self.uses_single_block_twap(i, i + 100) {
                    vulnerabilities.push(TwapManipulationShortWindowVulnerability::SingleBlockTwap {
                        description: "TWAP calculated within single block - instantly manipulable".to_string(),
                        location: i,
                    });
                }
                
                if !self.enforces_minimum_observations(i, i + 100) {
                    vulnerabilities.push(TwapManipulationShortWindowVulnerability::NoMinimumObservations {
                        description: "TWAP without minimum observation count check".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_twap_calculation(&self, location: usize) -> bool {
        if location + 40 > self.bytecode.len() {
            return false;
        }
        
        // TWAP involves: observe() or consult() calls, timestamp arithmetic
        let has_timestamp = self.bytecode[location..location + 40].iter().any(|&b| b == 0x42);
        let has_div = self.bytecode[location..location + 40].iter().any(|&b| b == 0x04);
        
        // Uniswap V3 observe() selector: 0x883bdbfd
        let has_observe = self.bytecode[location..location + 40].windows(4).any(|w| w == [0x88, 0x3b, 0xdb, 0xfd]);
        
        (has_timestamp && has_div) || has_observe
    }
    
    fn get_time_window(&self, start: usize, end: usize) -> Option<u64> {
        let range_end = end.min(self.bytecode.len());
        
        // Look for time constant (in seconds)
        for i in start..range_end.saturating_sub(4) {
            if self.bytecode[i] == 0x61 || self.bytecode[i] == 0x62 { // PUSH2 or PUSH3
                let bytes_to_read = if self.bytecode[i] == 0x61 { 2 } else { 3 };
                if i + bytes_to_read < range_end {
                    let mut value = 0u64;
                    for j in 0..bytes_to_read {
                        value = (value << 8) | (self.bytecode[i + 1 + j] as u64);
                    }
                    // Likely time window if between 1 min and 24 hours
                    if value >= 60 && value <= 86400 {
                        return Some(value);
                    }
                }
            }
        }
        
        None
    }
    
    fn uses_single_block_twap(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Single block TWAP: no secondsAgo array, or secondsAgo = [0]
        // Check if there's no historical timestamp loading
        let timestamp_count = self.bytecode[start..range_end].iter().filter(|&&b| b == 0x42).count();
        
        timestamp_count <= 1
    }
    
    fn enforces_minimum_observations(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Check for observation count validation
        self.bytecode[start..range_end].windows(2).any(|w| {
            (w[0] == 0x10 || w[0] == 0x11) && w[1] == 0xFD // Comparison + revert
        })
    }
}
