use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaDashboardPrivilegeEscalationVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct GrafanaDashboardPrivilegeEscalationDetector {
    bytecode: Vec<u8>,
}

impl GrafanaDashboardPrivilegeEscalationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<GrafanaDashboardPrivilegeEscalationVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_dashboard_api_key_exposure());
        vulnerabilities.extend(self.detect_template_variable_injection());
        vulnerabilities.extend(self.detect_datasource_proxy_bypass());
        vulnerabilities
    }

    fn detect_dashboard_api_key_exposure(&self) -> Vec<GrafanaDashboardPrivilegeEscalationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x54 { // SLOAD (API key read)
                let window_end = (pc + 100).min(self.bytecode.len());
                let exposes_in_event = self.bytecode[pc..window_end].iter().any(|&b| b == 0xA1);
                if exposes_in_event {
                    let encrypts_key = self.bytecode[pc..window_end].iter().any(|&b| b == 0x20);
                    if !encrypts_key {
                        vulns.push(GrafanaDashboardPrivilegeEscalationVulnerability {
                            pc, vulnerability_type: "DashboardApiKeyExposure".to_string(),
                            description: format!("Grafana API key read at PC {} exposed in event logs, allowing privilege escalation. Attack: contract stores Grafana service account API key for dashboard provisioning, emits key in logs, attacker reads logs, uses key to access/modify all dashboards. Real vulnerability: emit DashboardCreated(dashboardId, apiKey), Grafana service account key has Admin role, attacker extracts key from logs, calls Grafana API to create admin user. Example: contract holds Grafana API key with Editor permissions, logs 'Created dashboard with key=glsa_...', attacker uses key to modify production dashboards inserting malicious panels. Missing: never log secrets, use short-lived tokens, implement key rotation. Should implement: store only key hash, generate temporary tokens for operations, rotate keys after exposure. Fix: emit only dashboard ID, use Grafana OAuth instead of API keys, implement service account with minimal permissions (Viewer only).", pc),
                            confidence: 0.88,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_template_variable_injection(&self) -> Vec<GrafanaDashboardPrivilegeEscalationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xA2 { // LOG2 (dashboard update)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let uses_user_input = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 2;
                if uses_user_input {
                    let sanitizes_variables = self.bytecode[start..pc].iter().filter(|&&b| b == 0x1A).count() >= 1;
                    if !sanitizes_variables {
                        vulns.push(GrafanaDashboardPrivilegeEscalationVulnerability {
                            pc, vulnerability_type: "TemplateVariableInjection".to_string(),
                            description: format!("Dashboard template variable at PC {} accepts unsanitized user input, allowing query injection. Attack: contract creates Grafana dashboard with template variable from user input, attacker injects malicious PromQL/SQL breaking out of query context. Real attack: template variable $user_filter with query 'metric{{user=\"$user_filter\"}}', attacker inputs '\"}} or 1==1 {{dummy=\"', creates query 'metric{{user=\"\"}} or 1==1 {{dummy=\"\"}}', returns all data bypassing filters. Example: dashboard panel queries SELECT * FROM metrics WHERE user='$username', attacker inputs 'admin' OR '1'='1, SQL injection exposes all users' data. Missing: validate template variable format, use parameterized queries, escape special characters. Should implement: whitelist allowed variable values, use regex validation ^[a-zA-Z0-9_-]+$, escape quotes and braces. Fix: use Grafana's built-in variable type constraints (constant, custom, query with value validation), never construct queries via string concatenation.", pc),
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

    fn detect_datasource_proxy_bypass(&self) -> Vec<GrafanaDashboardPrivilegeEscalationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF1 { // CALL (datasource configuration)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let configures_datasource = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 3;
                if configures_datasource {
                    let validates_url = self.bytecode[start..pc].iter().any(|&b| b == 0x14);
                    if !validates_url {
                        vulns.push(GrafanaDashboardPrivilegeEscalationVulnerability {
                            pc, vulnerability_type: "DatasourceProxyBypass".to_string(),
                            description: format!("Grafana datasource configuration at PC {} doesn't validate URL, allowing SSRF via proxy bypass. Attack: contract provisions Grafana datasource with user-supplied URL, attacker provides internal URL, Grafana server proxies requests exposing internal services. Real vulnerability: datasource URL = userInput, attacker sets URL='http://localhost:9090/api/v1/query?query=up', Grafana proxies query to internal Prometheus, attacker extracts internal metrics. Example: create Prometheus datasource with url='http://169.254.169.254/latest/meta-data/', Grafana fetches AWS credentials via SSRF, attacker reads from dashboard query results. Missing: whitelist allowed datasource hosts, validate URL scheme and domain. Should implement: require datasource URL matches ^https?://(prometheus|influxdb)\\.company\\.com, reject private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16). Fix: use Grafana datasource permissions, implement network egress filtering, validate URLs against allowlist before provisioning.", pc),
                            confidence: 0.81,
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
