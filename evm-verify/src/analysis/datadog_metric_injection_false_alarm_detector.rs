use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatadogMetricInjectionVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct DatadogMetricInjectionFalseAlarmDetector {
    bytecode: Vec<u8>,
}

impl DatadogMetricInjectionFalseAlarmDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<DatadogMetricInjectionVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_unsanitized_metric_tags());
        vulnerabilities.extend(self.detect_metric_name_injection());
        vulnerabilities.extend(self.detect_cardinality_explosion());
        vulnerabilities
    }

    fn detect_unsanitized_metric_tags(&self) -> Vec<DatadogMetricInjectionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xA1 { // LOG1 (metric emission)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let uses_user_input = self.bytecode[start..pc].iter().any(|&b| b == 0x35);
                if uses_user_input {
                    let sanitizes_input = self.bytecode[start..pc].iter().filter(|&&b| b == 0x1A).count() >= 2;
                    if !sanitizes_input {
                        vulns.push(DatadogMetricInjectionVulnerability {
                            pc, vulnerability_type: "UnsanitizedMetricTags".to_string(),
                            description: format!("Datadog metric emission at PC {} uses unsanitized user input in tags, allowing injection. Attack: contract emits metrics with tags derived from calldata, attacker injects malicious tag values causing Datadog cardinality explosion or false alarms. Real vulnerability: metric tagged with user_address:{{user}}, attacker submits address='prod:true,region:us-east', creates fake tags triggering production alerts. Example: emit Metric(name, value, tags: 'env:' + userInput), attacker inputs 'prod,critical_service:api', creates metric with tags [env:prod, critical_service:api], triggers false alert in production monitoring. Missing: whitelist allowed tag values, sanitize special characters (comma, colon, newline). Should implement: require tag values match [a-zA-Z0-9_-], reject if contains Datadog delimiter characters. Fix: use tag allowlist, validate format before emission, or hash user inputs for tag values.", pc),
                            confidence: 0.84,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_metric_name_injection(&self) -> Vec<DatadogMetricInjectionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xA2 { // LOG2 (metric with name)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let constructs_name_dynamically = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 2;
                if constructs_name_dynamically {
                    let validates_namespace = self.bytecode[start..pc].iter().any(|&b| b == 0x14);
                    if !validates_namespace {
                        vulns.push(DatadogMetricInjectionVulnerability {
                            pc, vulnerability_type: "MetricNameInjection".to_string(),
                            description: format!("Metric name construction at PC {} allows injection into Datadog namespace. Attack: contract constructs metric name from user input, attacker injects periods to create fake namespace hierarchy spoofing legitimate metrics. Real attack: metric name = 'custom.' + userFunction, attacker calls with function='system.cpu.usage', creates metric 'custom.system.cpu.usage' appearing as system metric. Example: protocol tracks 'defi.protocol.tvl', attacker injects metric 'defi.protocol.tvl' with fake high value, monitoring dashboard shows inflated TVL, investors misled. Missing: fixed metric namespace prefix, validate no period injection. Should implement: const METRIC_PREFIX = 'myapp.custom.'; metricName = METRIC_PREFIX + sanitize(userInput). Fix: use metric name allowlist, reject names containing multiple periods, enforce namespace ownership.", pc),
                            confidence: 0.80,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_cardinality_explosion(&self) -> Vec<DatadogMetricInjectionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (metric state update)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let has_unbounded_tags = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 3;
                if has_unbounded_tags {
                    let limits_cardinality = self.bytecode[start..pc].iter().any(|&b| b == 0x10);
                    if !limits_cardinality {
                        vulns.push(DatadogMetricInjectionVulnerability {
                            pc, vulnerability_type: "CardinalityExplosion".to_string(),
                            description: format!("Metric emission at PC {} creates unbounded tag combinations, causing Datadog cardinality explosion and false alarms. Attack: each unique tag combination creates separate time series in Datadog, attacker submits requests with unique tag values, explodes cardinality, triggers Datadog billing alerts and quota limits. Real vulnerability: metric tagged with user_id, transaction_hash, block_number as high-cardinality tags, millions of unique combinations. Example: emit metric 'transaction.processed' with tags [user:{{address}}, tx:{{hash}}], 1M users * 1M txs = 1 trillion time series, Datadog rejects ingestion, monitoring breaks. Missing: limit tag cardinality, use tag value bucketing. Should implement: max 100 unique values per tag, group high-cardinality values into buckets. Fix: use address prefix (first 8 chars) instead of full address, bucket timestamps into 5-minute windows, aggregate transaction counts instead of per-tx metrics.", pc),
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
