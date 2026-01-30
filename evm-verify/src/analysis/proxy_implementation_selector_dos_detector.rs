use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyImplementationSelectorDosVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ProxyImplementationSelectorDosDetector {
    bytecode: Vec<u8>,
}

impl ProxyImplementationSelectorDosDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ProxyImplementationSelectorDosVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_unbounded_selector_iteration());
        vulnerabilities.extend(self.detect_selector_collision_dos());
        vulnerabilities.extend(self.detect_fallback_loop_griefing());
        vulnerabilities
    }

    fn detect_unbounded_selector_iteration(&self) -> Vec<ProxyImplementationSelectorDosVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x57 { // JUMPI (selector matching loop)
                let start = if pc > 150 { pc - 150 } else { 0 };
                let has_calldataload = self.bytecode[start..pc].iter().any(|&b| b == 0x35);
                if has_calldataload {
                    let has_iteration = self.bytecode[start..pc].iter().filter(|&&b| b == 0x57).count() >= 2;
                    if has_iteration {
                        let has_iteration_limit = self.bytecode[start..pc].iter().filter(|&&b| b == 0x10).count() >= 2;
                        if !has_iteration_limit {
                            vulns.push(ProxyImplementationSelectorDosVulnerability {
                                pc, vulnerability_type: "UnboundedSelectorIteration".to_string(),
                                description: format!("Proxy selector matching at PC {} iterates without bounds, allowing DoS via gas exhaustion. Attack: Diamond proxy iterates through all facets to find function selector, attacker calls non-existent function, loop executes checking every facet until gas exhausted, transaction reverts blocking proxy. Real vulnerability: DiamondCutFacet with 100 facets, each facet checked sequentially via JUMPI loop, function not found after 100 iterations, consumes 2M gas before reverting. Example: attacker calls proxy.nonExistentFunction(), loop checks facet[0].supportsInterface, facet[1].supportsInterface, ..., facet[99].supportsInterface, all fail, gas limit hit, legitimate transactions in same block unable to execute. Missing: iteration limit, binary search for selectors, function existence precheck. Should implement: require(iterationCount < MAX_FACETS), or use mapping for O(1) selector lookup instead of O(n) iteration. Fix: replace sequential facet iteration with mapping(bytes4 => address) selectorToFacet, single SLOAD instead of loop.", pc),
                                confidence: 0.83,
                            });
                        }
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_selector_collision_dos(&self) -> Vec<ProxyImplementationSelectorDosVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x14 { // EQ (selector comparison)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let has_selector_read = self.bytecode[start..pc].iter().any(|&b| b == 0x35);
                if has_selector_read {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let validates_unique = self.bytecode[start..window_end].iter().filter(|&&b| b == 0x14).count() >= 3;
                    if !validates_unique {
                        vulns.push(ProxyImplementationSelectorDosVulnerability {
                            pc, vulnerability_type: "SelectorCollisionDos".to_string(),
                            description: format!("Selector collision check at PC {} doesn't validate uniqueness, allowing DoS via duplicate selectors. Attack: proxy allows adding facets with duplicate function selectors, first match always executes, subsequent implementations unreachable, legitimate functionality DoS'd. Real attack: DiamondProxy.diamondCut adds facet with selector 0x12345678, attacker frontuns adding malicious facet with same selector, proxy uses first match, attacker's facet executes for all calls. Example: protocol upgrades adding withdraw(uint256) selector 0xabcdef12, attacker adds facet with withdraw() also hashing to 0xabcdef12 (collision via selector grinding), attacker's withdraw called instead, funds stolen. Missing: check for selector collisions before adding facet. Should implement: require(selectorToFacet[selector] == address(0), 'SelectorExists'), prevent duplicate registration. Fix: maintain mapping of existing selectors, revert on collision, use commit-reveal for facet additions.", pc),
                            confidence: 0.79,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_fallback_loop_griefing(&self) -> Vec<ProxyImplementationSelectorDosVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF4 { // DELEGATECALL (proxy delegation)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let in_fallback = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() == 0;
                if in_fallback {
                    let window_end = (pc + 100).min(self.bytecode.len());
                    let has_gas_limit = self.bytecode[start..window_end].iter().filter(|&&b| b == 0x5A).count() >= 1;
                    if !has_gas_limit {
                        vulns.push(ProxyImplementationSelectorDosVulnerability {
                            pc, vulnerability_type: "FallbackLoopGriefing".to_string(),
                            description: format!("Proxy fallback delegatecall at PC {} forwards all gas, allowing griefing via infinite loop. Attack: proxy fallback delegates to implementation with receive() containing infinite loop, attacker sends ETH to proxy, all gas consumed in loop, transaction reverts after wasting caller's gas. Real vulnerability: minimal proxy pattern delegates fallback to implementation, implementation's fallback has while(true) loop, caller loses entire gas limit. Example: proxy receives 1 ETH with 10M gas, delegates to implementation.fallback(), implementation runs infinite loop, consumes all 10M gas, reverts, caller loses gas fees. Missing: gas stipend limit, fallback protection. Should implement: delegatecall with limited gas, e.g., implementation.delegatecall{{gas: 100000}}(data). Fix: add gas limit to delegatecall, implement receive() separately from fallback, add reentrancy guard to fallback function.", pc),
                            confidence: 0.77,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
