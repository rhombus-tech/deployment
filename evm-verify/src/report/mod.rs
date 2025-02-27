use crate::bytecode::types::{AnalysisResults, DelegateCall};
use serde::{Serialize, Deserialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use anyhow::Result;
use chrono;

/// Report format options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// JSON format
    Json,
    /// Markdown format
    Markdown,
    /// HTML format
    Html,
}

/// Report generator for bytecode analysis results
pub struct ReportGenerator {
    /// Analysis results
    results: AnalysisResults,
    /// Contract name or address
    contract_name: String,
    /// Report format
    format: ReportFormat,
}

/// Serializable report structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    /// Contract name or address
    pub contract_name: String,
    /// Analysis timestamp
    pub timestamp: String,
    /// Code length
    pub code_length: usize,
    /// Number of memory accesses
    pub memory_access_count: usize,
    /// Number of storage accesses
    pub storage_access_count: usize,
    /// Security warnings
    pub warnings: Vec<String>,
    /// Delegate calls
    pub delegate_calls: Vec<DelegateCallInfo>,
    /// Severity summary
    pub severity_summary: SeveritySummary,
}

/// Delegate call information for reports
#[derive(Debug, Serialize, Deserialize)]
pub struct DelegateCallInfo {
    /// Program counter
    pub pc: usize,
    /// Target address
    pub target: String,
    /// Depth
    pub depth: usize,
}

/// Severity summary for reports
#[derive(Debug, Serialize, Deserialize)]
pub struct SeveritySummary {
    /// Number of critical issues
    pub critical: usize,
    /// Number of high severity issues
    pub high: usize,
    /// Number of medium severity issues
    pub medium: usize,
    /// Number of low severity issues
    pub low: usize,
    /// Number of informational issues
    pub info: usize,
}

impl ReportGenerator {
    /// Create a new report generator
    pub fn new(results: AnalysisResults, contract_name: String, format: ReportFormat) -> Self {
        Self {
            results,
            contract_name,
            format,
        }
    }

    /// Generate a report and return it as a string
    pub fn generate(&self) -> Result<String> {
        // Create report structure
        let report = self.create_report_structure();
        
        // Generate report in the specified format
        match self.format {
            ReportFormat::Json => self.generate_json(report),
            ReportFormat::Markdown => self.generate_markdown(report),
            ReportFormat::Html => self.generate_html(report),
        }
    }
    
    /// Save report to a file
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let report_content = self.generate()?;
        let mut file = File::create(path)?;
        file.write_all(report_content.as_bytes())?;
        Ok(())
    }
    
    /// Create the report structure
    fn create_report_structure(&self) -> Report {
        // Count severity levels
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut info = 0;
        
        // Simple heuristic to estimate severity based on warning text
        for warning in &self.results.warnings {
            if warning.contains("reentrancy") {
                high += 1;
            } else if warning.contains("overflow") || warning.contains("underflow") {
                medium += 1;
            } else if warning.contains("delegate call") {
                critical += 1;
            } else {
                low += 1;
            }
        }
        
        // Create delegate call info
        let delegate_calls = self.results.delegate_calls.iter()
            .map(|call| DelegateCallInfo {
                pc: call.pc as usize,
                target: format!("{:?}", call.target),
                depth: call.depth as usize,
            })
            .collect();
        
        // Create timestamp
        let timestamp = chrono::Local::now().to_rfc3339();
        
        Report {
            contract_name: self.contract_name.clone(),
            timestamp,
            code_length: self.results.runtime.code_length,
            memory_access_count: self.results.memory_accesses.len(),
            storage_access_count: self.results.storage.len(),
            warnings: self.results.warnings.clone(),
            delegate_calls,
            severity_summary: SeveritySummary {
                critical,
                high,
                medium,
                low,
                info,
            },
        }
    }
    
    /// Generate JSON report
    fn generate_json(&self, report: Report) -> Result<String> {
        Ok(serde_json::to_string_pretty(&report)?)
    }
    
    /// Generate Markdown report
    fn generate_markdown(&self, report: Report) -> Result<String> {
        let mut md = String::new();
        
        // Title
        md.push_str(&format!("# Security Analysis Report: {}\n\n", report.contract_name));
        
        // Summary
        md.push_str("## Summary\n\n");
        md.push_str(&format!("- **Contract**: {}\n", report.contract_name));
        md.push_str(&format!("- **Analysis Date**: {}\n", report.timestamp));
        md.push_str(&format!("- **Code Size**: {} bytes\n", report.code_length));
        md.push_str(&format!("- **Memory Accesses**: {}\n", report.memory_access_count));
        md.push_str(&format!("- **Storage Accesses**: {}\n", report.storage_access_count));
        md.push_str(&format!("- **Total Issues**: {}\n\n", report.warnings.len()));
        
        // Severity breakdown
        md.push_str("## Severity Breakdown\n\n");
        md.push_str("| Severity | Count |\n");
        md.push_str("|----------|-------|\n");
        md.push_str(&format!("| Critical | {} |\n", report.severity_summary.critical));
        md.push_str(&format!("| High | {} |\n", report.severity_summary.high));
        md.push_str(&format!("| Medium | {} |\n", report.severity_summary.medium));
        md.push_str(&format!("| Low | {} |\n", report.severity_summary.low));
        md.push_str(&format!("| Informational | {} |\n\n", report.severity_summary.info));
        
        // Findings
        md.push_str("## Findings\n\n");
        for (i, warning) in report.warnings.iter().enumerate() {
            md.push_str(&format!("### Issue #{}\n\n", i + 1));
            md.push_str(&format!("{}\n\n", warning));
        }
        
        // Delegate Calls
        if !report.delegate_calls.is_empty() {
            md.push_str("## Delegate Calls\n\n");
            md.push_str("| PC | Target | Depth |\n");
            md.push_str("|-----|--------|-------|\n");
            for call in &report.delegate_calls {
                md.push_str(&format!("| {} | {} | {} |\n", call.pc, call.target, call.depth));
            }
            md.push_str("\n");
        }
        
        // Recommendations
        md.push_str("## Recommendations\n\n");
        md.push_str("1. Review all potential reentrancy vulnerabilities and ensure proper guards are in place\n");
        md.push_str("2. Implement checks for arithmetic operations to prevent overflow/underflow\n");
        md.push_str("3. Carefully audit delegate calls to ensure they cannot be exploited\n");
        md.push_str("4. Follow the checks-effects-interactions pattern for all external calls\n");
        md.push_str("5. Consider using OpenZeppelin's security contracts for standardized protections\n");
        
        Ok(md)
    }
    
    /// Generate HTML report
    fn generate_html(&self, report: Report) -> Result<String> {
        let mut html = String::new();
        
        // HTML header
        html.push_str("<!DOCTYPE html>\n");
        html.push_str("<html lang=\"en\">\n");
        html.push_str("<head>\n");
        html.push_str("  <meta charset=\"UTF-8\">\n");
        html.push_str("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.push_str(&format!("  <title>Security Analysis: {}</title>\n", report.contract_name));
        html.push_str("  <style>\n");
        html.push_str("    body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }\n");
        html.push_str("    h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }\n");
        html.push_str("    h2 { color: #2980b9; margin-top: 30px; }\n");
        html.push_str("    h3 { color: #3498db; }\n");
        html.push_str("    .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; }\n");
        html.push_str("    .critical { color: #e74c3c; }\n");
        html.push_str("    .high { color: #e67e22; }\n");
        html.push_str("    .medium { color: #f39c12; }\n");
        html.push_str("    .low { color: #27ae60; }\n");
        html.push_str("    .info { color: #3498db; }\n");
        html.push_str("    table { width: 100%; border-collapse: collapse; margin: 20px 0; }\n");
        html.push_str("    th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }\n");
        html.push_str("    th { background-color: #f2f2f2; }\n");
        html.push_str("    tr:hover { background-color: #f5f5f5; }\n");
        html.push_str("    .finding { background-color: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #3498db; }\n");
        html.push_str("  </style>\n");
        html.push_str("</head>\n");
        html.push_str("<body>\n");
        
        // Title
        html.push_str(&format!("  <h1>Security Analysis Report: {}</h1>\n", report.contract_name));
        
        // Summary
        html.push_str("  <div class=\"summary\">\n");
        html.push_str("    <h2>Summary</h2>\n");
        html.push_str("    <p>\n");
        html.push_str(&format!("      <strong>Contract:</strong> {}<br>\n", report.contract_name));
        html.push_str(&format!("      <strong>Analysis Date:</strong> {}<br>\n", report.timestamp));
        html.push_str(&format!("      <strong>Code Size:</strong> {} bytes<br>\n", report.code_length));
        html.push_str(&format!("      <strong>Memory Accesses:</strong> {}<br>\n", report.memory_access_count));
        html.push_str(&format!("      <strong>Storage Accesses:</strong> {}<br>\n", report.storage_access_count));
        html.push_str(&format!("      <strong>Total Issues:</strong> {}\n", report.warnings.len()));
        html.push_str("    </p>\n");
        html.push_str("  </div>\n");
        
        // Severity breakdown
        html.push_str("  <h2>Severity Breakdown</h2>\n");
        html.push_str("  <table>\n");
        html.push_str("    <tr><th>Severity</th><th>Count</th></tr>\n");
        html.push_str(&format!("    <tr><td class=\"critical\">Critical</td><td>{}</td></tr>\n", report.severity_summary.critical));
        html.push_str(&format!("    <tr><td class=\"high\">High</td><td>{}</td></tr>\n", report.severity_summary.high));
        html.push_str(&format!("    <tr><td class=\"medium\">Medium</td><td>{}</td></tr>\n", report.severity_summary.medium));
        html.push_str(&format!("    <tr><td class=\"low\">Low</td><td>{}</td></tr>\n", report.severity_summary.low));
        html.push_str(&format!("    <tr><td class=\"info\">Informational</td><td>{}</td></tr>\n", report.severity_summary.info));
        html.push_str("  </table>\n");
        
        // Findings
        html.push_str("  <h2>Findings</h2>\n");
        for (i, warning) in report.warnings.iter().enumerate() {
            html.push_str("  <div class=\"finding\">\n");
            html.push_str(&format!("    <h3>Issue #{}</h3>\n", i + 1));
            html.push_str(&format!("    <p>{}</p>\n", warning));
            html.push_str("  </div>\n");
        }
        
        // Delegate Calls
        if !report.delegate_calls.is_empty() {
            html.push_str("  <h2>Delegate Calls</h2>\n");
            html.push_str("  <table>\n");
            html.push_str("    <tr><th>PC</th><th>Target</th><th>Depth</th></tr>\n");
            for call in &report.delegate_calls {
                html.push_str(&format!("    <tr><td>{}</td><td>{}</td><td>{}</td></tr>\n", 
                    call.pc, call.target, call.depth));
            }
            html.push_str("  </table>\n");
        }
        
        // Recommendations
        html.push_str("  <h2>Recommendations</h2>\n");
        html.push_str("  <ol>\n");
        html.push_str("    <li>Review all potential reentrancy vulnerabilities and ensure proper guards are in place</li>\n");
        html.push_str("    <li>Implement checks for arithmetic operations to prevent overflow/underflow</li>\n");
        html.push_str("    <li>Carefully audit delegate calls to ensure they cannot be exploited</li>\n");
        html.push_str("    <li>Follow the checks-effects-interactions pattern for all external calls</li>\n");
        html.push_str("    <li>Consider using OpenZeppelin's security contracts for standardized protections</li>\n");
        html.push_str("  </ol>\n");
        
        // HTML footer
        html.push_str("</body>\n");
        html.push_str("</html>\n");
        
        Ok(html)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::types::{RuntimeAnalysis, MemoryAnalysis};
    
    #[test]
    fn test_report_generation() -> Result<()> {
        // Create sample analysis results
        let results = AnalysisResults {
            constructor: Default::default(),
            runtime: RuntimeAnalysis {
                code_length: 1000,
                ..Default::default()
            },
            storage: vec![],
            memory: MemoryAnalysis::default(),
            warnings: vec![
                "Potential reentrancy vulnerability detected: state changes after external call".to_string(),
                "Potential integer overflow detected in arithmetic operation".to_string(),
                "Unprotected delegate call detected".to_string(),
            ],
            memory_accesses: vec![],
            delegate_calls: vec![
                DelegateCall {
                    target: Default::default(),
                    data_offset: Default::default(),
                    data_size: Default::default(),
                    return_offset: Default::default(),
                    return_size: Default::default(),
                    pc: 123,
                    parent_call_id: None,
                    child_call_ids: vec![],
                    state_modifications: vec![],
                    gas_limit: Default::default(),
                    gas_used: Default::default(),
                    depth: 1,
                }
            ],
        };
        
        // Create report generator
        let generator = ReportGenerator::new(
            results,
            "TestContract".to_string(),
            ReportFormat::Json
        );
        
        // Generate JSON report
        let json_report = generator.generate()?;
        assert!(json_report.contains("TestContract"));
        assert!(json_report.contains("reentrancy"));
        
        // Create markdown report generator
        let md_generator = ReportGenerator::new(
            generator.results.clone(),
            "TestContract".to_string(),
            ReportFormat::Markdown
        );
        
        // Generate Markdown report
        let md_report = md_generator.generate()?;
        assert!(md_report.contains("# Security Analysis Report: TestContract"));
        assert!(md_report.contains("## Findings"));
        
        // Create HTML report generator
        let html_generator = ReportGenerator::new(
            generator.results.clone(),
            "TestContract".to_string(),
            ReportFormat::Html
        );
        
        // Generate HTML report
        let html_report = html_generator.generate()?;
        assert!(html_report.contains("<title>Security Analysis: TestContract</title>"));
        assert!(html_report.contains("<h2>Findings</h2>"));
        
        Ok(())
    }
}
