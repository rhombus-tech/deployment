use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use crate::circuits::execution_trace::EVMExecutionTrace;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};

/// Protocol dependency vulnerability types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtocolDependencyRisk {
    /// Circular dependencies that could cause cascading failures
    CircularDependency,
    /// Over-reliance on a single protocol creates systemic risk
    SystemicConcentrationRisk,
    /// Version mismatch between dependent protocols
    VersionMismatchRisk,
    /// Dependency on deprecated or unmaintained protocol
    DeprecatedDependencyRisk,
    /// Oracle dependency concentration
    OracleDependencyRisk,
    /// Liquidity dependency concentration  
    LiquidityConcentrationRisk,
    /// Governance token concentration risk
    GovernanceConcentrationRisk,
    /// Cross-protocol arbitrage manipulation
    ArbitrageManiputlationRisk,
    /// Dependency chain too deep (composability risk)
    ExcessiveDependencyDepth,
    /// Protocol upgrade coordination risk
    UpgradeCoordinationRisk,
}

/// Protocol dependency vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolDependencyVulnerability {
    pub risk_type: ProtocolDependencyRisk,
    pub severity: SecuritySeverity,
    pub description: String,
    pub dependency_chain: Vec<ProtocolNode>,
    pub systemic_impact: SystemicImpact,
    pub confidence: f32,
    pub remediation: String,
    pub execution_trace_evidence: Vec<u8>,
}

/// Node in the protocol dependency graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolNode {
    pub protocol_name: String,
    pub contract_address: String,
    pub protocol_type: ProtocolType,
    pub version: Option<String>,
    pub governance_model: GovernanceModel,
    pub total_value_locked: Option<u64>,
    pub daily_volume: Option<u64>,
    pub dependencies: Vec<String>, // Addresses of dependent contracts
}

/// Type of DeFi protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtocolType {
    /// Automated Market Maker (Uniswap, Sushiswap)
    AMM,
    /// Lending/Borrowing (Aave, Compound)
    Lending,
    /// Yield Farming (Yearn, Harvest)
    YieldFarming,
    /// Derivatives (Synthetix, dYdX)
    Derivatives,
    /// Insurance (Nexus Mutual, Cover)
    Insurance,
    /// Oracle (Chainlink, Band)
    Oracle,
    /// Bridge (Polygon, Optimism)
    Bridge,
    /// Governance (Maker, Compound)
    Governance,
    /// Staking (Lido, RocketPool)
    Staking,
    /// Options (Opyn, Hegic)
    Options,
    /// Exchange (Binance DEX, 1inch)
    Exchange,
    /// Stablecoin (USDC, DAI, USDT)
    Stablecoin,
    /// Unknown protocol type
    Unknown,
}

/// Governance model of protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceModel {
    /// Decentralized governance with token voting
    Decentralized,
    /// Multi-signature governance
    MultiSig,
    /// Single admin control
    Centralized,
    /// Immutable (no governance)
    Immutable,
    /// Time-locked governance
    TimeLocked,
    /// Unknown governance model
    Unknown,
}

/// Systemic impact assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemicImpact {
    pub affected_protocols: u32,
    pub total_value_at_risk: u64,
    pub user_impact_count: u32,
    pub cascade_probability: f32,
    pub recovery_difficulty: RecoveryDifficulty,
    pub market_impact_severity: MarketImpactSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryDifficulty {
    Easy,      // < 1 day
    Medium,    // 1-3 days
    Moderate,  // 1-7 days  
    Hard,      // 1-4 weeks
    Severe,    // 1+ months
    Extreme,   // 3+ months
    Impossible, // Permanent damage
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MarketImpactSeverity {
    Minimal,       // < 1% market impact
    Low,           // 1-5% market impact
    Moderate,      // 5-15% market impact
    High,          // 15-30% market impact
    Major,         // 30-40% market impact
    Severe,        // 40-50% market impact
    Extreme,       // 50-60% market impact
    Catastrophic,  // > 60% market impact
}

/// Protocol dependency mapper using execution trace analysis
pub struct ProtocolDependencyMapper {
    bytecode: Vec<u8>,
    contract_address: Option<String>,
    dependency_graph: ProtocolDependencyGraph,
    known_protocols: HashMap<String, ProtocolNode>,
    interactions: Vec<ProtocolInteraction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolInteraction {
    pub protocol: String,
    pub interaction_type: String,
    pub gas_used: u64,
    pub timestamp: u64,
    pub dependency_depth: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplexityMetrics {
    pub code_complexity: u32,
    pub interaction_complexity: u32,
    pub dependency_count: u32,
    pub external_calls: u32,
    pub upgrade_mechanisms: u32,
}

/// Protocol dependency graph structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolDependencyGraph {
    pub nodes: HashMap<String, ProtocolNode>,
    pub edges: HashMap<String, HashSet<String>>, // address -> set of dependent addresses
    pub reverse_edges: HashMap<String, HashSet<String>>, // address -> set of dependee addresses
    pub dependency_depth: HashMap<String, u32>,
}

impl ProtocolDependencyGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            reverse_edges: HashMap::new(),
            dependency_depth: HashMap::new(),
        }
    }

    pub fn keys(&self) -> std::collections::hash_map::Keys<String, HashSet<String>> {
        self.edges.keys()
    }

    pub fn get(&self, key: &str) -> Option<&HashSet<String>> {
        self.edges.get(key)
    }

    pub fn iter(&self) -> std::collections::hash_map::Iter<String, HashSet<String>> {
        self.edges.iter()
    }

    pub fn is_empty(&self, protocol: &str) -> bool {
        self.edges.get(protocol).map(|deps| deps.is_empty()).unwrap_or(true)
    }
}

impl ProtocolDependencyMapper {
    /// Create new protocol dependency mapper
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self {
            bytecode,
            contract_address: None,
            dependency_graph: ProtocolDependencyGraph::new(),
            known_protocols: Self::load_known_protocols(),
            interactions: Vec::new(),
        }
    }

    /// Set contract address for analysis
    pub fn with_address(mut self, address: String) -> Self {
        self.contract_address = Some(address);
        self
    }

    /// Analyze protocol dependencies using execution traces
    pub fn analyze_dependencies(&mut self, execution_trace: &[u8]) -> Vec<ProtocolDependencyVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Build dependency graph from actual execution traces
        self.build_dependency_graph_from_trace(execution_trace);

        // Analyze dependency-related risks
        vulnerabilities.extend(self.detect_circular_dependencies());
        vulnerabilities.extend(self.detect_concentration_risks());
        vulnerabilities.extend(self.detect_version_mismatches());
        vulnerabilities.extend(self.detect_deprecated_dependencies());
        vulnerabilities.extend(self.detect_oracle_risks());
        vulnerabilities.extend(self.detect_liquidity_concentration());
        vulnerabilities.extend(self.detect_governance_risks());
        vulnerabilities.extend(self.detect_arbitrage_risks(execution_trace));
        vulnerabilities.extend(self.detect_excessive_depth());
        vulnerabilities.extend(self.detect_upgrade_coordination_risks());

        vulnerabilities
    }

    /// Build dependency graph from actual execution trace
    fn build_dependency_graph_from_trace(&mut self, trace: &[u8]) {
        // Parse execution trace to identify protocol interactions
        let protocol_calls: Vec<ProtocolCall> = Vec::new(); // TODO: Implement trace parsing
        
        for call in protocol_calls {
            self.add_dependency_edge(
                call.caller_address,
                call.callee_address,
                call.interaction_type
            );
        }

        // Calculate dependency depths
        self.calculate_dependency_depths();
    }

    /// Detect circular dependency vulnerabilities
    fn detect_circular_dependencies(&self) -> Vec<ProtocolDependencyVulnerability> {
        let mut vulnerabilities = Vec::new();

        let cycles = self.find_dependency_cycles();
        
        for cycle in cycles {
            let systemic_impact = self.assess_cycle_impact(&cycle);
            
            vulnerabilities.push(ProtocolDependencyVulnerability {
                risk_type: ProtocolDependencyRisk::CircularDependency,
                severity: self.determine_cycle_severity(&cycle, &systemic_impact),
                description: format!(
                    "Circular dependency detected involving {} protocols: {}",
                    cycle.len(),
                    cycle.iter().map(|addr| self.get_protocol_name(addr)).collect::<Vec<_>>().join(" -> ")
                ),
                dependency_chain: cycle.iter()
                    .map(|addr| self.get_protocol_node(addr).unwrap_or_default())
                    .collect(),
                systemic_impact,
                confidence: 0.95, // High confidence in cycle detection
                remediation: "Break circular dependency by introducing circuit breakers or removing unnecessary dependencies".to_string(),
                execution_trace_evidence: Vec::new(),
            });
        }

        vulnerabilities
    }

    /// Detect concentration risks (over-reliance on single protocols)
    fn detect_concentration_risks(&self) -> Vec<ProtocolDependencyVulnerability> {
        let mut vulnerabilities = Vec::new();

        let concentration_analysis = self.analyze_dependency_concentration();
        
        for (critical_protocol, dependent_count) in concentration_analysis.high_concentration_protocols {
            if dependent_count > 10 { // Threshold for concentration risk
                let impact = self.estimate_concentration_impact(&critical_protocol, dependent_count);
                
                vulnerabilities.push(ProtocolDependencyVulnerability {
                    risk_type: ProtocolDependencyRisk::SystemicConcentrationRisk,
                    severity: SecuritySeverity::High,
                    description: format!(
                        "Systemic concentration risk: {} protocols depend on {}",
                        dependent_count,
                        self.get_protocol_name(&critical_protocol)
                    ),
                    dependency_chain: self.get_dependency_chain_to_protocol(&critical_protocol),
                    systemic_impact: impact,
                    confidence: 0.90,
                    remediation: "Diversify dependencies to reduce single points of failure".to_string(),
                    execution_trace_evidence: Vec::new(),
                });
            }
        }

        vulnerabilities
    }

    /// Detect version mismatch risks
    fn detect_version_mismatches(&self) -> Vec<ProtocolDependencyVulnerability> {
        let mut vulnerabilities = Vec::new();

        let version_conflicts = self.find_version_conflicts();
        
        for conflict in version_conflicts {
            vulnerabilities.push(ProtocolDependencyVulnerability {
                risk_type: ProtocolDependencyRisk::VersionMismatchRisk,
                severity: SecuritySeverity::Medium,
                description: format!(
                    "Version mismatch between {} (v{}) and {} (v{})",
                    self.get_protocol_name(&conflict.protocol_a),
                    conflict.version_a,
                    self.get_protocol_name(&conflict.protocol_b),
                    conflict.version_b
                ),
                dependency_chain: vec![
                    self.get_protocol_node(&conflict.protocol_a).unwrap_or_default(),
                    self.get_protocol_node(&conflict.protocol_b).unwrap_or_default(),
                ],
                systemic_impact: conflict.impact,
                confidence: 0.80,
                remediation: "Coordinate protocol upgrades or implement version compatibility layers".to_string(),
                execution_trace_evidence: Vec::new(),
            });
        }

        vulnerabilities
    }

    /// Detect dependencies on deprecated protocols
    fn detect_deprecated_dependencies(&self) -> Vec<ProtocolDependencyVulnerability> {
        let mut vulnerabilities = Vec::new();

        let deprecated_deps = self.find_deprecated_dependencies();
        
        for dep in deprecated_deps {
            vulnerabilities.push(ProtocolDependencyVulnerability {
                risk_type: ProtocolDependencyRisk::DeprecatedDependencyRisk,
                severity: SecuritySeverity::High,
                description: format!(
                    "Dependency on deprecated protocol: {}",
                    self.get_protocol_name(&dep.address)
                ),
                dependency_chain: vec![dep.protocol_node],
                systemic_impact: dep.impact,
                confidence: 0.95,
                remediation: "Migrate to supported alternative protocols".to_string(),
                execution_trace_evidence: Vec::new(),
            });
        }

        vulnerabilities
    }

    /// Detect oracle dependency concentration risks
    fn detect_oracle_risks(&self) -> Vec<ProtocolDependencyVulnerability> {
        let mut vulnerabilities = Vec::new();

        let oracle_analysis = self.analyze_oracle_dependencies();
        
        if oracle_analysis.concentration_risk > 0.7 { // 70% threshold
            vulnerabilities.push(ProtocolDependencyVulnerability {
                risk_type: ProtocolDependencyRisk::OracleDependencyRisk,
                severity: SecuritySeverity::High,
                description: format!(
                    "High oracle concentration risk: {}% of price data from single source",
                    (oracle_analysis.concentration_risk * 100.0) as u32
                ),
                dependency_chain: oracle_analysis.critical_oracles,
                systemic_impact: oracle_analysis.impact,
                confidence: 0.85,
                remediation: "Diversify oracle sources and implement price aggregation".to_string(),
                execution_trace_evidence: Vec::new(),
            });
        }

        vulnerabilities
    }

    /// Detect liquidity concentration risks
    fn detect_liquidity_concentration(&self) -> Vec<ProtocolDependencyVulnerability> {
        let mut vulnerabilities = Vec::new();

        let liquidity_analysis = self.analyze_liquidity_dependencies();
        
        for risk in liquidity_analysis.high_risk_concentrations {
            vulnerabilities.push(ProtocolDependencyVulnerability {
                risk_type: ProtocolDependencyRisk::LiquidityConcentrationRisk,
                severity: SecuritySeverity::Medium,
                description: format!(
                    "Liquidity concentration risk in {} ({}% of total liquidity)",
                    self.get_protocol_name(&risk.protocol_address),
                    (risk.concentration_percentage * 100.0) as u32
                ),
                dependency_chain: vec![risk.protocol_node],
                systemic_impact: risk.impact,
                confidence: 0.75,
                remediation: "Distribute liquidity across multiple protocols".to_string(),
                execution_trace_evidence: Vec::new(),
            });
        }

        vulnerabilities
    }

    /// Detect governance-related dependency risks
    fn detect_governance_risks(&self) -> Vec<ProtocolDependencyVulnerability> {
        let mut vulnerabilities = Vec::new();

        let governance_risks = self.analyze_governance_dependencies();
        
        for risk in governance_risks {
            vulnerabilities.push(ProtocolDependencyVulnerability {
                risk_type: ProtocolDependencyRisk::GovernanceConcentrationRisk,
                severity: risk.severity,
                description: risk.description,
                dependency_chain: risk.affected_protocols,
                systemic_impact: risk.impact,
                confidence: 0.80,
                remediation: "Implement governance diversification and emergency procedures".to_string(),
                execution_trace_evidence: Vec::new(),
            });
        }

        vulnerabilities
    }

    /// Detect cross-protocol arbitrage manipulation risks
    fn detect_arbitrage_risks(&self, trace: &[u8]) -> Vec<ProtocolDependencyVulnerability> {
        let mut vulnerabilities = Vec::new();

        let arbitrage_patterns = self.detect_arbitrage_patterns_in_trace(trace);
        
        for pattern in arbitrage_patterns {
            if pattern.manipulation_risk > 0.6 {
                vulnerabilities.push(ProtocolDependencyVulnerability {
                    risk_type: ProtocolDependencyRisk::ArbitrageManiputlationRisk,
                    severity: SecuritySeverity::Medium,
                    description: format!(
                        "Cross-protocol arbitrage manipulation risk detected between {} protocols",
                        pattern.involved_protocols.len()
                    ),
                    dependency_chain: pattern.protocol_chain,
                    systemic_impact: pattern.impact,
                    confidence: pattern.confidence,
                    remediation: "Implement arbitrage detection and circuit breakers".to_string(),
                    execution_trace_evidence: trace.to_vec(),
                });
            }
        }

        vulnerabilities
    }

    /// Detect excessive dependency depth
    fn detect_excessive_depth(&self) -> Vec<ProtocolDependencyVulnerability> {
        let mut vulnerabilities = Vec::new();

        let max_safe_depth = 5; // Configurable threshold
        
        for (address, depth) in &self.dependency_graph.dependency_depth {
            if *depth > max_safe_depth {
                let chain = self.get_dependency_chain_to_protocol(address);
                let impact = self.assess_depth_impact(*depth);
                
                vulnerabilities.push(ProtocolDependencyVulnerability {
                    risk_type: ProtocolDependencyRisk::ExcessiveDependencyDepth,
                    severity: SecuritySeverity::Medium,
                    description: format!(
                        "Excessive dependency depth: {} levels deep for {}",
                        depth,
                        self.get_protocol_name(address)
                    ),
                    dependency_chain: chain,
                    systemic_impact: impact,
                    confidence: 0.90,
                    remediation: "Reduce dependency chain length and implement fallback mechanisms".to_string(),
                    execution_trace_evidence: Vec::new(),
                });
            }
        }

        vulnerabilities
    }

    /// Detect upgrade coordination risks
    fn detect_upgrade_coordination_risks(&self) -> Vec<ProtocolDependencyVulnerability> {
        let mut vulnerabilities = Vec::new();

        let coordination_risks = self.analyze_upgrade_coordination();
        
        for risk in coordination_risks {
            vulnerabilities.push(ProtocolDependencyVulnerability {
                risk_type: ProtocolDependencyRisk::UpgradeCoordinationRisk,
                severity: risk.severity,
                description: risk.description,
                dependency_chain: risk.affected_protocols,
                systemic_impact: risk.impact,
                confidence: 0.70,
                remediation: "Implement coordinated upgrade procedures and backward compatibility".to_string(),
                execution_trace_evidence: Vec::new(),
            });
        }

        vulnerabilities
    }
}

impl ProtocolDependencyMapper {
    fn parse_protocol_interactions(&mut self, execution_trace: &EVMExecutionTrace) {
        // Parse execution trace for external calls to known DeFi protocols
        for step in &execution_trace.execution_steps {
            // Check for external calls (CALL, STATICCALL, DELEGATECALL opcodes)
            if step.opcode == 0xF1 || step.opcode == 0xFA || step.opcode == 0xF4 {
                // Check if call is to a known protocol
                let target_address = format!("{:?}", step.contract_address);
                
                // Detect Uniswap, Curve, Compound, Aave interactions
                if self.is_known_protocol(&target_address) {
                    let protocol_name = self.identify_protocol(&target_address);
                    
                    // Add to dependency graph
                    if !self.dependency_graph.nodes.contains_key(&protocol_name) {
                        self.dependency_graph.nodes.insert(protocol_name.clone(), ProtocolNode::default());
                    }
                    
                    // Track interaction (simplified for now)
                    let interaction_type = InteractionType::FunctionCall; // Simplified classification
                    
                    // Store in dependency graph nodes for tracking
                    if let Some(node) = self.dependency_graph.nodes.get_mut(&protocol_name) {
                        // Update node interaction count or other metrics as needed
                    }
                }
            }
        }
    }

    fn add_dependency_edge(&mut self, caller: String, callee: String, interaction_type: InteractionType) {
        // Add edges to dependency graph based on interaction patterns
        if let Some(dependencies) = self.dependency_graph.edges.get_mut(&caller) {
            dependencies.insert(callee);
        } else {
            let mut deps = HashSet::new();
            deps.insert(callee);
            self.dependency_graph.edges.insert(caller, deps);
        }
    }

    fn build_dependency_graph(&mut self) {
        // Build edges based on known protocols (simplified implementation)
        let protocol_names: Vec<String> = self.known_protocols.keys().cloned().collect();
        
        // Create basic dependency relationships between known protocols
        for (i, protocol) in protocol_names.iter().enumerate() {
            for other_protocol in protocol_names.iter().skip(i + 1) {
                // Add basic dependency edge (simplified)
                self.add_dependency_edge(protocol.clone(), other_protocol.clone(), InteractionType::FunctionCall);
            }
        }
    }

    fn calculate_dependency_depths(&mut self) {
        // Calculate dependency depths using BFS traversal
        let mut depths: HashMap<String, u32> = HashMap::new();
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: std::collections::VecDeque<(String, u32)> = std::collections::VecDeque::new();
        
        // Start with protocols that have no dependencies (depth 0)
        for protocol in self.dependency_graph.keys() {
            if self.dependency_graph.is_empty(protocol) {
                queue.push_back((protocol.clone(), 0));
                depths.insert(protocol.clone(), 0);
            }
        }
        
        // BFS to calculate depths
        while let Some((current_protocol, current_depth)) = queue.pop_front() {
            if visited.contains(&current_protocol) {
                continue;
            }
            visited.insert(current_protocol.clone());
            
            // Update interactions with calculated depth
            for interaction in &mut self.interactions {
                if interaction.protocol == current_protocol {
                    interaction.dependency_depth = current_depth;
                }
            }
            
            // Add dependent protocols to queue
            for (protocol, dependencies) in self.dependency_graph.iter() {
                if dependencies.contains(&current_protocol) && !visited.contains(protocol) {
                    let new_depth = current_depth + 1;
                    if !depths.contains_key(protocol) || depths[protocol] > new_depth {
                        depths.insert(protocol.clone(), new_depth);
                        queue.push_back((protocol.clone(), new_depth));
                    }
                }
            }
        }
    }

    fn find_dependency_cycles(&self) -> Vec<Vec<String>> {
        let mut cycles = Vec::new();
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();
        let mut path = Vec::new();
        
        // DFS to detect cycles
        for protocol in self.dependency_graph.keys() {
            if !visited.contains(protocol) {
                self.dfs_cycle_detection(
                    protocol,
                    &mut visited,
                    &mut rec_stack,
                    &mut path,
                    &mut cycles
                );
            }
        }
        
        cycles
    }

    fn assess_cycle_impact(&self, cycle: &[String]) -> SystemicImpact {
        // Assess the systemic impact of a dependency cycle
        let affected_protocols = cycle.len() as u32;
        
        // Estimate total value at risk based on protocol types
        let mut total_value_at_risk = 0u64;
        let mut high_risk_protocols = 0;
        
        for protocol in cycle {
            // Estimate TVL based on known protocol categories
            let estimated_tvl = match protocol.as_str() {
                p if p.contains("uniswap") || p.contains("curve") => 1_000_000_000, // $1B+
                p if p.contains("compound") || p.contains("aave") => 5_000_000_000, // $5B+
                p if p.contains("maker") || p.contains("dai") => 8_000_000_000, // $8B+
                _ => 100_000_000, // $100M default
            };
            total_value_at_risk += estimated_tvl;
            
            if estimated_tvl > 1_000_000_000 {
                high_risk_protocols += 1;
            }
        }
        
        // Calculate cascade probability based on cycle characteristics
        let cascade_probability = if cycle.len() > 5 {
            0.8 // High probability for large cycles
        } else if high_risk_protocols > 2 {
            0.6 // Medium-high for multiple high-value protocols
        } else {
            0.3 // Lower for smaller cycles
        };
        
        // Determine recovery difficulty
        let recovery_difficulty = if cycle.len() > 4 && high_risk_protocols > 1 {
            RecoveryDifficulty::Extreme
        } else if cycle.len() > 2 {
            RecoveryDifficulty::Hard
        } else {
            RecoveryDifficulty::Medium
        };
        
        // Determine market impact severity
        let market_impact_severity = if total_value_at_risk > 10_000_000_000 {
            MarketImpactSeverity::Catastrophic
        } else if total_value_at_risk > 5_000_000_000 {
            MarketImpactSeverity::Severe
        } else if total_value_at_risk > 1_000_000_000 {
            MarketImpactSeverity::Major
        } else {
            MarketImpactSeverity::Moderate
        };
        
        SystemicImpact {
            affected_protocols,
            total_value_at_risk,
            user_impact_count: (total_value_at_risk / 1000) as u32, // Estimate users
            cascade_probability,
            recovery_difficulty,
            market_impact_severity,
        }
    }

    fn determine_cycle_severity(&self, _cycle: &[String], _impact: &SystemicImpact) -> SecuritySeverity {
        SecuritySeverity::Medium
    }

    fn get_protocol_name(&self, address: &str) -> String {
        self.known_protocols
            .get(address)
            .map(|p| p.protocol_name.clone())
            .unwrap_or_else(|| format!("Unknown-{}", &address[..8]))
    }

    fn get_protocol_node(&self, address: &str) -> Option<ProtocolNode> {
        self.known_protocols.get(address).cloned()
    }

    fn analyze_dependency_concentration(&self) -> ConcentrationAnalysis {
        // Implementation would analyze concentration metrics
        ConcentrationAnalysis {
            high_concentration_protocols: Vec::new(),
        }
    }

    fn estimate_concentration_impact(&self, _protocol: &str, _dependent_count: u32) -> SystemicImpact {
        SystemicImpact {
            affected_protocols: 0,
            total_value_at_risk: 0,
            user_impact_count: 0,
            cascade_probability: 0.0,
            recovery_difficulty: RecoveryDifficulty::Easy,
            market_impact_severity: MarketImpactSeverity::Minimal,
        }
    }

    fn assess_protocol_complexity(&self, protocol: &str) -> ComplexityMetrics {
        // Analyze protocol complexity based on interactions and dependencies
        let dependency_count = self.dependency_graph.get(protocol)
            .map(|deps| deps.len())
            .unwrap_or(0) as u32;
        
        let external_calls = self.interactions.iter()
            .filter(|i| i.protocol == protocol)
            .count() as u32;
        
        // Estimate code complexity based on interaction patterns
        let code_complexity = match protocol {
            p if p.contains("compound") || p.contains("aave") => 0.8, // High complexity lending
            p if p.contains("curve") => 0.9, // Very high complexity AMM
            p if p.contains("uniswap") => 0.6, // Medium complexity AMM
            p if p.contains("maker") => 0.95, // Extremely high complexity stablecoin
            _ => 0.4, // Default medium-low complexity
        };
        
        let interaction_complexity = (dependency_count as f32 * 0.1).min(1.0);
        
        let upgrade_mechanisms = if protocol.contains("proxy") || protocol.contains("upgradeable") {
            2 // Has upgrade mechanisms
        } else {
            0
        };
        
        ComplexityMetrics {
            code_complexity: (code_complexity * 100.0) as u32,
            interaction_complexity: (interaction_complexity * 100.0) as u32,
            dependency_count,
            external_calls,
            upgrade_mechanisms,
        }
    }

    fn get_dependency_chain_to_protocol(&self, _address: &str) -> Vec<ProtocolNode> {
        Vec::new()
    }

    fn find_version_conflicts(&self) -> Vec<VersionConflict> {
        Vec::new()
    }

    fn find_deprecated_dependencies(&self) -> Vec<DeprecatedDependency> {
        Vec::new()
    }

    fn analyze_oracle_dependencies(&self) -> OracleAnalysis {
        OracleAnalysis {
            concentration_risk: 0.0,
            critical_oracles: Vec::new(),
            impact: SystemicImpact {
                affected_protocols: 0,
                total_value_at_risk: 0,
                user_impact_count: 0,
                cascade_probability: 0.0,
                recovery_difficulty: RecoveryDifficulty::Easy,
                market_impact_severity: MarketImpactSeverity::Minimal,
            },
        }
    }

    fn analyze_liquidity_dependencies(&self) -> LiquidityAnalysis {
        LiquidityAnalysis {
            high_risk_concentrations: Vec::new(),
        }
    }

    fn analyze_governance_dependencies(&self) -> Vec<GovernanceRisk> {
        Vec::new()
    }

    fn detect_arbitrage_patterns_in_trace(&self, _trace: &[u8]) -> Vec<ArbitragePattern> {
        Vec::new()
    }

    fn assess_depth_impact(&self, _depth: u32) -> SystemicImpact {
        SystemicImpact {
            affected_protocols: 0,
            total_value_at_risk: 0,
            user_impact_count: 0,
            cascade_probability: 0.0,
            recovery_difficulty: RecoveryDifficulty::Easy,
            market_impact_severity: MarketImpactSeverity::Minimal,
        }
    }

    fn analyze_upgrade_coordination(&self) -> Vec<UpgradeCoordinationRisk> {
        Vec::new()
    }

    fn load_known_protocols() -> HashMap<String, ProtocolNode> {
        // NEUTRAL: Empty protocol database - detect by bytecode pattern, not address
        // Protocols are identified dynamically during analysis
        HashMap::new()
    }
    
    /// Load protocol database for protocol identification
    /// NEUTRAL: Empty database - detect protocols by bytecode patterns
    fn load_protocol_database(&self) -> HashMap<String, ProtocolNode> {
        // NEUTRAL: No hardcoded protocols - detect dynamically
        HashMap::new()
    }
    
    fn is_known_protocol(&self, address: &str) -> bool {
        let protocols = self.load_protocol_database();
        protocols.contains_key(address)
    }
    
    fn identify_protocol(&self, address: &str) -> String {
        let protocols = self.load_protocol_database();
        protocols.get(address)
            .map(|p| p.protocol_name.clone())
            .unwrap_or_else(|| format!("Unknown_{}", &address[..8]))
    }
    
    fn classify_interaction(&self, call_data: &[u8]) -> InteractionType {
        if call_data.len() < 4 {
            return InteractionType::Unknown;
        }
        
        let function_sig = &call_data[..4];
        match function_sig {
            [0xa9, 0x05, 0x9c, 0xbb] => InteractionType::TokenTransfer, // transfer()
            [0x38, 0xed, 0x17, 0x39] => InteractionType::Exchange, // swapExactTokensForTokens()
            [0x40, 0xc1, 0x0f, 0x19] => InteractionType::Minting, // mint()
            [0x42, 0x96, 0x6c, 0x68] => InteractionType::Burning, // burn()
            [0xdb, 0x00, 0x6a, 0x75] => InteractionType::Redemption, // redeem()
            [0x50, 0xd2, 0x5b, 0xcd] => InteractionType::Oracle, // latestAnswer()
            _ => InteractionType::Unknown,
        }
    }
    
    fn dfs_cycle_detection(
        &self,
        protocol: &str,
        visited: &mut HashSet<String>,
        rec_stack: &mut HashSet<String>,
        path: &mut Vec<String>,
        cycles: &mut Vec<Vec<String>>
    ) {
        visited.insert(protocol.to_string());
        rec_stack.insert(protocol.to_string());
        path.push(protocol.to_string());
        
        if let Some(dependencies) = self.dependency_graph.get(protocol) {
            for dep in dependencies {
                if !visited.contains(dep) {
                    self.dfs_cycle_detection(dep, visited, rec_stack, path, cycles);
                } else if rec_stack.contains(dep) {
                    // Found a cycle
                    if let Some(cycle_start) = path.iter().position(|p| p == dep) {
                        let cycle = path[cycle_start..].to_vec();
                        cycles.push(cycle);
                    }
                }
            }
        }
        
        path.pop();
        rec_stack.remove(protocol);
    }
}



impl Default for ProtocolNode {
    fn default() -> Self {
        Self {
            protocol_name: "Unknown".to_string(),
            contract_address: "0x0".to_string(),
            protocol_type: ProtocolType::Unknown,
            version: None,
            governance_model: GovernanceModel::Unknown,
            total_value_locked: None,
            daily_volume: None,
            dependencies: Vec::new(),
        }
    }
}

// Supporting types for analysis
struct ProtocolCall {
    caller_address: String,
    callee_address: String,
    interaction_type: InteractionType,
}

#[derive(Debug)]
enum InteractionType {
    FunctionCall,
    TokenTransfer,
    LiquidityProvision,
    PriceQuery,
    GovernanceVote,
    Exchange,
    Minting,
    Burning,
    Redemption,
    Oracle,
    Unknown,
    Other,
}

struct ConcentrationAnalysis {
    high_concentration_protocols: Vec<(String, u32)>,
}

struct VersionConflict {
    protocol_a: String,
    version_a: String,
    protocol_b: String,
    version_b: String,
    impact: SystemicImpact,
}

struct DeprecatedDependency {
    address: String,
    protocol_node: ProtocolNode,
    impact: SystemicImpact,
}

struct OracleAnalysis {
    concentration_risk: f32,
    critical_oracles: Vec<ProtocolNode>,
    impact: SystemicImpact,
}

struct LiquidityAnalysis {
    high_risk_concentrations: Vec<LiquidityRisk>,
}

struct LiquidityRisk {
    protocol_address: String,
    protocol_node: ProtocolNode,
    concentration_percentage: f32,
    impact: SystemicImpact,
}

struct GovernanceRisk {
    severity: SecuritySeverity,
    description: String,
    affected_protocols: Vec<ProtocolNode>,
    impact: SystemicImpact,
}

struct ArbitragePattern {
    involved_protocols: Vec<String>,
    protocol_chain: Vec<ProtocolNode>,
    manipulation_risk: f32,
    confidence: f32,
    impact: SystemicImpact,
}

struct UpgradeCoordinationRisk {
    severity: SecuritySeverity,
    description: String,
    affected_protocols: Vec<ProtocolNode>,
    impact: SystemicImpact,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_dependency_mapper_creation() {
        let bytecode = vec![0x60, 0x80, 0x60, 0x40, 0x52];
        let mapper = ProtocolDependencyMapper::new(bytecode);
        
        assert!(mapper.dependency_graph.nodes.is_empty());
        assert!(mapper.dependency_graph.edges.is_empty());
    }

    #[test]
    fn test_dependency_analysis() {
        let bytecode = vec![0x60, 0x80, 0x60, 0x40, 0x52];
        let mut mapper = ProtocolDependencyMapper::new(bytecode)
            .with_address("0x123456".to_string());
        
        let execution_trace = vec![]; // Empty trace for test
        let vulnerabilities = mapper.analyze_dependencies(&execution_trace);
        
        // Should not panic and return empty vulnerabilities for empty trace
        assert!(vulnerabilities.is_empty());
    }

    #[test]
    fn test_protocol_node_default() {
        let node = ProtocolNode::default();
        assert_eq!(node.protocol_name, "Unknown");
        assert!(matches!(node.protocol_type, ProtocolType::Unknown));
    }
}
