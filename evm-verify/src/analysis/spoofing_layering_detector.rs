use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpoofingVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct SpoofingLayeringDetector {
    bytecode: Vec<u8>,
}

impl SpoofingLayeringDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SpoofingVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_order_spoofing());
        vulnerabilities.extend(self.detect_layering_manipulation());
        vulnerabilities.extend(self.detect_quote_stuffing());

        vulnerabilities
    }

    fn detect_order_spoofing(&self) -> Vec<SpoofingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (order placement)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_order_book = window.iter().filter(|&&b| b == 0x54).count() >= 2; // Multiple SLOADs
                let has_price_impact = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                
                if has_order_book {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_cancellation_penalty = window.iter().any(|&b| b == 0x03); // SUB (fee)
                    let has_minimum_fill_time = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    if !has_cancellation_penalty && !has_minimum_fill_time {
                        vulns.push(SpoofingVulnerability {
                            pc,
                            vulnerability_type: "OrderSpoofing".to_string(),
                            description: format!(
                                "Order book at PC {} vulnerable to spoofing manipulation. Attack: place large buy orders to create false demand signal, other traders see \
                                apparent buying pressure and buy, cancel spoof orders before execution, sell into inflated price. Intent: never execute spoof orders, just \
                                manipulate price perception. Example: place $10M buy order, market moves up, real buyers enter, cancel spoof order, sell to real buyers. \
                                Missing: order cancellation penalties, minimum order lifetime, fill-or-kill enforcement, commitment bonds. Should require: orders live for \
                                minimum time or charge cancellation fee proportional to order size.",
                                pc
                            ),
                            confidence: 0.85,
                        });
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

    fn detect_layering_manipulation(&self) -> Vec<SpoofingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (price level access)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_multiple_price_levels = window.iter().filter(|&&b| b == 0x54).count() >= 3;
                let has_order_execution = window.iter().any(|&b| b == 0xF1); // CALL
                
                if has_multiple_price_levels && has_order_execution {
                    let has_anti_layering = window.iter().filter(|&&b| b == 0x20).count() >= 2; // Pattern detection
                    
                    if !has_anti_layering {
                        vulns.push(SpoofingVulnerability {
                            pc,
                            vulnerability_type: "LayeringManipulation".to_string(),
                            description: format!(
                                "Multi-level order book at PC {} vulnerable to layering. Attack: (1) place real order on one side (buy at $100), (2) place multiple spoof \
                                orders on opposite side (sell at $101, $102, $103), (3) spoof orders push perceived price up, (4) real order gets filled at better price, \
                                (5) cancel spoof orders. Like spoofing but uses multiple price levels. Example: want to buy, layer sell orders above to suppress price, \
                                buy cheap, remove sell layers. Missing: same-address multi-level detection, rapid order-cancel pattern analysis, layering score tracking. \
                                Should implement: penalties for orders at multiple price levels with high cancel rates.",
                                pc
                            ),
                            confidence: 0.83,
                        });
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

    fn detect_quote_stuffing(&self) -> Vec<SpoofingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP (rate limiting check)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_order_processing = window.iter().filter(|&&b| b == 0x55).count() >= 2; // Multiple SSTOREs
                
                if has_order_processing {
                    let has_rate_limit = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    let has_order_throttle = window.iter().filter(|&&b| b == 0x42).count() >= 2;
                    
                    if !has_rate_limit {
                        vulns.push(SpoofingVulnerability {
                            pc,
                            vulnerability_type: "QuoteStuffing".to_string(),
                            description: format!(
                                "Order processing at PC {} lacks rate limiting for quote stuffing defense. Attack: flood order book with high-frequency quote updates to \
                                create market noise and slow down other traders' systems. Place and cancel thousands of orders per second. Purpose: (1) mask real trading \
                                intent, (2) create latency for competitors, (3) trigger opponent algorithms into errors, (4) monopolize order book bandwidth. In TradFi: \
                                illegal market manipulation. Missing: per-address order rate limits, minimum order lifetime, quote-to-trade ratio limits, progressive fees \
                                for high update rates. Should implement: exponentially increasing fees for rapid order updates.",
                                pc
                            ),
                            confidence: 0.81,
                        });
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
