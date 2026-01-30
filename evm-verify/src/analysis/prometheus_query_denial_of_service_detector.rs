use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrometheusQueryDosVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct PrometheusQueryDenialOfServiceDetector {
    bytecode: Vec<u8>,
}

impl PrometheusQueryDenialOfServiceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<PrometheusQueryDosVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_unbounded_label_matching());
        vulnerabilities.extend(self.detect_expensive_aggregation_query());
        vulnerabilities.extend(self.detect_time_range_explosion());
        vulnerabilities
    }

    fn detect_unbounded_label_matching(&self) -> Vec<PrometheusQueryDosVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xA3 { // LOG3 (metric query pattern)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let uses_regex_matcher = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 2;
                if uses_regex_matcher {
                    let limits_query_scope = self.bytecode[start..pc].iter().any(|&b| b == 0x10);
                    if !limits_query_scope {
                        vulns.push(PrometheusQueryDosVulnerability {
                            pc, vulnerability_type: "UnboundedLabelMatching".to_string(),
                            description: format!("Prometheus query pattern at PC {} allows unbounded label regex, causing query DoS. Attack: contract constructs PromQL query with user-supplied regex pattern, attacker provides '.*' matching all labels, Prometheus scans entire TSDB. Real attack: query pattern metric{{label=~'{{userPattern}}'}}, attacker inputs '.*|.*|.*', creates exponential backtracking regex, Prometheus CPU spikes to 100%, monitoring unavailable. Example: query http_requests_total{{endpoint=~'USER_INPUT'}}, attacker provides '/api/.*|/web/.*|/mobile/.*' with nested alternation, regex engine takes minutes to evaluate against millions of series. Missing: validate regex complexity, limit pattern length, whitelist allowed label matchers. Should implement: reject regex containing nested quantifiers, limit to 50 chars, require anchored patterns. Fix: use exact label matching instead of regex, or validate pattern against regex complexity analyzer before query execution.", pc),
                            confidence: 0.86,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_expensive_aggregation_query(&self) -> Vec<PrometheusQueryDosVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x02 { // MUL (metric aggregation)
                let start = if pc > 150 { pc - 150 } else { 0 };
                let has_aggregation_pattern = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 3;
                if has_aggregation_pattern {
                    let limits_series_count = self.bytecode[start..pc].iter().filter(|&&b| b == 0x10).count() >= 1;
                    if !limits_series_count {
                        vulns.push(PrometheusQueryDosVulnerability {
                            pc, vulnerability_type: "ExpensiveAggregationQuery".to_string(),
                            description: format!("Prometheus aggregation at PC {} creates expensive query without series limits. Attack: contract emits PromQL with aggregation operators over unbounded time series, Prometheus OOMs processing billions of datapoints. Real vulnerability: query sum(rate(metric{{}}[5m])), metric has 1M unique label combinations, Prometheus computes rate for each series then sums, requires loading 1M * 300 datapoints = 300M points into memory. Example: user triggers query count(metric{{user=~'.*'}}), matches all users, aggregates over 10M series, Prometheus allocates 10GB RAM, query times out after 2 minutes. Missing: limit series cardinality in aggregations, use recording rules for expensive queries. Should implement: max 10000 series per aggregation, require pre-aggregated metrics for high-cardinality queries. Fix: replace real-time aggregation with recording rules evaluated periodically, add series count estimation before query execution.", pc),
                            confidence: 0.82,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_time_range_explosion(&self) -> Vec<PrometheusQueryDosVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x42 { // TIMESTAMP (time range calculation)
                let window_end = (pc + 100).min(self.bytecode.len());
                let has_range_calc = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x03).count() >= 2;
                if has_range_calc {
                    let validates_max_range = self.bytecode[pc..window_end].iter().any(|&b| b == 0x10);
                    if !validates_max_range {
                        vulns.push(PrometheusQueryDosVulnerability {
                            pc, vulnerability_type: "TimeRangeExplosion".to_string(),
                            description: format!("Time range calculation at PC {} allows unbounded query duration, causing Prometheus DoS. Attack: contract constructs PromQL query with user-supplied time range, attacker requests 1 year of data, Prometheus scans billions of samples. Real attack: query metric[{{userDuration}}], attacker provides duration='365d', Prometheus loads 1 year * 12 samples/min * 1000 series = 6.3B samples, exhausts memory and CPU. Example: dashboard query http_requests_total[START:END], attacker sets START=0, END=now(), query spans entire metric history (years), Prometheus blocks for minutes processing query. Missing: maximum time range validation, typically 24 hours for instant queries, 7 days for range queries. Should implement: require duration < 24h, reject queries with range > MAX_QUERY_RANGE. Fix: enforce query time limits in contract logic, use subqueries with bounded ranges, implement query result caching with TTL.", pc),
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
}
