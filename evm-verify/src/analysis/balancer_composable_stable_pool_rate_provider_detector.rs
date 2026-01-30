use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalancerRateProviderVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct BalancerComposableStablePoolRateProviderDetector {
    bytecode: Vec<u8>,
}

impl BalancerComposableStablePoolRateProviderDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<BalancerRateProviderVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_malicious_rate_provider());
        vulnerabilities.extend(self.detect_rate_provider_reentrancy());
        vulnerabilities.extend(self.detect_rate_staleness_exploit());

        vulnerabilities
    }

    fn detect_malicious_rate_provider(&self) -> Vec<BalancerRateProviderVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xFA { // STATICCALL (getRate from rate provider)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_rate_provider_call = window.iter().any(|&b| b == 0x54); // SLOAD (rate provider address)
                
                if has_rate_provider_call {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_rate_bounds_check = forward.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    let has_rate_sanity_check = forward.iter().any(|&b| b == 0x14); // EQ
                    
                    if !has_rate_bounds_check {
                        vulns.push(BalancerRateProviderVulnerability {
                            pc,
                            vulnerability_type: "MaliciousRateProvider".to_string(),
                            description: format!(
                                "Balancer Composable Pool rate provider call at PC {} without validation. Rate providers are external contracts returning \
                                exchange rates for wrapped tokens (wstETH, rETH). Attack: malicious/compromised rate provider returns extreme rate (0 or 10^18), \
                                pool accepts invalid rate, invariant calculation breaks, infinite minting or draining. Missing: rate bounds validation (e.g., \
                                0.9 < rate < 1.1), rate change limit per block, rate provider whitelist/registry. Should enforce: MIN_RATE < rate < MAX_RATE.",
                                pc
                            ),
                            confidence: 0.89,
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

    fn detect_rate_provider_reentrancy(&self) -> Vec<BalancerRateProviderVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xFA { // STATICCALL (rate provider)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_pool_state_read = window.iter().any(|&b| b == 0x54); // SLOAD after rate call
                
                if has_pool_state_read {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_reentrancy_lock = pre_window.iter().filter(|&&b| b == 0x55).count() >= 2;
                    let has_view_enforcement = window.iter().any(|&b| b == 0xFA); // Multiple STATICCALL
                    
                    if !has_reentrancy_lock {
                        vulns.push(BalancerRateProviderVulnerability {
                            pc,
                            vulnerability_type: "RateProviderReentrancy".to_string(),
                            description: format!(
                                "Rate provider STATICCALL at PC {} allows read-only reentrancy. Even STATICCALL can reenter via view functions. Attack: \
                                malicious rate provider's getRate() calls back into pool's view function (getVirtualSupply), reads inconsistent state during \
                                swap, returns manipulated rate based on incomplete state. Missing: reentrancy guard before rate provider calls, state snapshot, \
                                view function reentrancy protection. Should use Balancer's VaultReentrancyLib._ensureNotInVaultContext().",
                                pc
                            ),
                            confidence: 0.86,
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

    fn detect_rate_staleness_exploit(&self) -> Vec<BalancerRateProviderVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x02 { // MUL (rate multiplication in invariant)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_rate_usage = window.iter().any(|&b| b == 0xFA); // STATICCALL (getRate)
                let has_invariant_calc = window.iter().filter(|&&b| b == 0x02).count() >= 3;
                
                if has_rate_usage && has_invariant_calc {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_rate_cache = window.iter().any(|&b| b == 0x54); // SLOAD (cached rate)
                    let has_cache_expiry = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    if has_rate_cache && !has_cache_expiry {
                        vulns.push(BalancerRateProviderVulnerability {
                            pc,
                            vulnerability_type: "RateStalenessExploit".to_string(),
                            description: format!(
                                "Cached rate usage at PC {} without expiry check. Balancer pools cache rates to save gas. Attack: rate provider's actual \
                                rate changes significantly (wstETH rebase, rETH exchange rate update), cached rate stale, pool uses old rate for swaps, \
                                arbitrage between pool rate and real rate. Missing: cache duration limit, rate deviation threshold for cache invalidation, \
                                forced cache update mechanism. Should check: block.timestamp - lastCacheUpdate <= CACHE_DURATION.",
                                pc
                            ),
                            confidence: 0.84,
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
