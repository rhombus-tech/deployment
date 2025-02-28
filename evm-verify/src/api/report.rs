// Report Generation for EVM Verify
//
// This module handles the generation and formatting of analysis reports.

use crate::api::types::{AnalysisReport, Vulnerability, VulnerabilitySeverity};
use anyhow::Result;
use std::path::Path;
use std::fs;
use serde_json;

/// Report formatter for EVM Verify
pub struct ReportFormatter;

impl ReportFormatter {
    /// Format a report as JSON
    pub fn to_json(report: &AnalysisReport) -> Result<String> {
        let json = serde_json::to_string_pretty(report)?;
        Ok(json)
    }
    
    /// Format a report as plain text
    pub fn to_text(report: &AnalysisReport) -> String {
        let mut output = String::new();
        
        // Header
        output.push_str(&format!("EVM Verify Analysis Report\n"));
        output.push_str(&format!("========================\n\n"));
        
        // Basic information
        output.push_str(&format!("Timestamp: {}\n", report.timestamp));
        output.push_str(&format!("Contract Size: {} bytes\n", report.contract_size));
        output.push_str(&format!("Delegate Calls: {}\n", report.delegate_calls));
        output.push_str(&format!("Memory Accesses: {}\n", report.memory_accesses));
        output.push_str(&format!("Storage Accesses: {}\n\n", report.storage_accesses));
        
        // Vulnerabilities
        output.push_str(&format!("Vulnerabilities: {}\n", report.vulnerabilities.len()));
        output.push_str(&format!("----------------\n\n"));
        
        // Group vulnerabilities by severity
        let mut critical = Vec::new();
        let mut high = Vec::new();
        let mut medium = Vec::new();
        let mut low = Vec::new();
        let mut info = Vec::new();
        let mut error = Vec::new();
        
        for vuln in &report.vulnerabilities {
            match vuln.severity {
                VulnerabilitySeverity::Critical => critical.push(vuln),
                VulnerabilitySeverity::High => high.push(vuln),
                VulnerabilitySeverity::Medium => medium.push(vuln),
                VulnerabilitySeverity::Low => low.push(vuln),
                VulnerabilitySeverity::Info => info.push(vuln),
                VulnerabilitySeverity::Error => error.push(vuln),
            }
        }
        
        // Format vulnerabilities by severity
        if !critical.is_empty() {
            output.push_str(&format!("CRITICAL: {} issues\n", critical.len()));
            Self::format_vulnerabilities(&mut output, &critical);
        }
        
        if !high.is_empty() {
            output.push_str(&format!("HIGH: {} issues\n", high.len()));
            Self::format_vulnerabilities(&mut output, &high);
        }
        
        if !medium.is_empty() {
            output.push_str(&format!("MEDIUM: {} issues\n", medium.len()));
            Self::format_vulnerabilities(&mut output, &medium);
        }
        
        if !low.is_empty() {
            output.push_str(&format!("LOW: {} issues\n", low.len()));
            Self::format_vulnerabilities(&mut output, &low);
        }
        
        if !info.is_empty() {
            output.push_str(&format!("INFO: {} issues\n", info.len()));
            Self::format_vulnerabilities(&mut output, &info);
        }
        
        if !error.is_empty() {
            output.push_str(&format!("ERROR: {} issues\n", error.len()));
            Self::format_vulnerabilities(&mut output, &error);
        }
        
        // Configuration
        output.push_str(&format!("\nAnalysis Configuration\n"));
        output.push_str(&format!("---------------------\n"));
        output.push_str(&format!("Analyze Constructor: {}\n", report.analysis_config.analyze_constructor));
        output.push_str(&format!("Analyze Runtime: {}\n", report.analysis_config.analyze_runtime));
        output.push_str(&format!("Max Depth: {}\n", report.analysis_config.max_depth));
        output.push_str(&format!("Detect Reentrancy: {}\n", report.analysis_config.detect_reentrancy));
        output.push_str(&format!("Detect Arithmetic: {}\n", report.analysis_config.detect_arithmetic));
        output.push_str(&format!("Detect Access Control: {}\n", report.analysis_config.detect_access_control));
        output.push_str(&format!("Detect Delegate Call: {}\n", report.analysis_config.detect_delegate_call));
        
        output
    }
    
    /// Format vulnerabilities for text output
    fn format_vulnerabilities(output: &mut String, vulnerabilities: &[&Vulnerability]) {
        for (i, vuln) in vulnerabilities.iter().enumerate() {
            output.push_str(&format!("{}. {}\n", i + 1, vuln.title));
            output.push_str(&format!("   Severity: {:?}\n", vuln.severity));
            output.push_str(&format!("   Type: {:?}\n", vuln.vulnerability_type));
            output.push_str(&format!("   Description: {}\n", vuln.description));
            output.push_str(&format!("   Recommendation: {}\n\n", vuln.recommendation));
        }
    }
    
    /// Save a report to a file
    pub fn save_to_file<P: AsRef<Path>>(report: &AnalysisReport, path: P, format: ReportFormat) -> Result<()> {
        let content = match format {
            ReportFormat::Json => Self::to_json(report)?,
            ReportFormat::Text => Self::to_text(report),
            ReportFormat::Html => Self::to_html(report),
        };
        
        fs::write(path, content)?;
        Ok(())
    }
    
    /// Format a report as HTML
    pub fn to_html(report: &AnalysisReport) -> String {
        let mut html = String::new();
        
        // HTML header
        html.push_str("<!DOCTYPE html>\n");
        html.push_str("<html lang=\"en\">\n");
        html.push_str("<head>\n");
        html.push_str("  <meta charset=\"UTF-8\">\n");
        html.push_str("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.push_str("  <title>EVM Verify Analysis Report</title>\n");
        html.push_str("  <style>\n");
        html.push_str("    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }\n");
        html.push_str("    h1 { color: #333; }\n");
        html.push_str("    .info-box { background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }\n");
        html.push_str("    .vuln-critical { background-color: #ffdddd; border-left: 5px solid #ff0000; padding: 10px; margin-bottom: 10px; }\n");
        html.push_str("    .vuln-high { background-color: #ffeeee; border-left: 5px solid #ff6600; padding: 10px; margin-bottom: 10px; }\n");
        html.push_str("    .vuln-medium { background-color: #ffffee; border-left: 5px solid #ffcc00; padding: 10px; margin-bottom: 10px; }\n");
        html.push_str("    .vuln-low { background-color: #eeffee; border-left: 5px solid #00cc00; padding: 10px; margin-bottom: 10px; }\n");
        html.push_str("    .vuln-info { background-color: #eeeeff; border-left: 5px solid #0066ff; padding: 10px; margin-bottom: 10px; }\n");
        html.push_str("    .vuln-error { background-color: #ffcccc; border-left: 5px solid #ff0000; padding: 10px; margin-bottom: 10px; }\n");
        html.push_str("  </style>\n");
        html.push_str("</head>\n");
        html.push_str("<body>\n");
        
        // Report header
        html.push_str("  <h1>EVM Verify Analysis Report</h1>\n");
        
        // Basic information
        html.push_str("  <div class=\"info-box\">\n");
        html.push_str(&format!("    <p><strong>Timestamp:</strong> {}</p>\n", report.timestamp));
        html.push_str(&format!("    <p><strong>Contract Size:</strong> {} bytes</p>\n", report.contract_size));
        html.push_str(&format!("    <p><strong>Delegate Calls:</strong> {}</p>\n", report.delegate_calls));
        html.push_str(&format!("    <p><strong>Memory Accesses:</strong> {}</p>\n", report.memory_accesses));
        html.push_str(&format!("    <p><strong>Storage Accesses:</strong> {}</p>\n", report.storage_accesses));
        html.push_str("  </div>\n");
        
        // Vulnerabilities
        html.push_str(&format!("  <h2>Vulnerabilities: {}</h2>\n", report.vulnerabilities.len()));
        
        // Group vulnerabilities by severity
        let mut critical = Vec::new();
        let mut high = Vec::new();
        let mut medium = Vec::new();
        let mut low = Vec::new();
        let mut info = Vec::new();
        let mut error = Vec::new();
        
        for vuln in &report.vulnerabilities {
            match vuln.severity {
                VulnerabilitySeverity::Critical => critical.push(vuln),
                VulnerabilitySeverity::High => high.push(vuln),
                VulnerabilitySeverity::Medium => medium.push(vuln),
                VulnerabilitySeverity::Low => low.push(vuln),
                VulnerabilitySeverity::Info => info.push(vuln),
                VulnerabilitySeverity::Error => error.push(vuln),
            }
        }
        
        // Format vulnerabilities by severity
        if !critical.is_empty() {
            html.push_str(&format!("  <h3>CRITICAL: {} issues</h3>\n", critical.len()));
            Self::format_vulnerabilities_html(&mut html, &critical, "vuln-critical");
        }
        
        if !high.is_empty() {
            html.push_str(&format!("  <h3>HIGH: {} issues</h3>\n", high.len()));
            Self::format_vulnerabilities_html(&mut html, &high, "vuln-high");
        }
        
        if !medium.is_empty() {
            html.push_str(&format!("  <h3>MEDIUM: {} issues</h3>\n", medium.len()));
            Self::format_vulnerabilities_html(&mut html, &medium, "vuln-medium");
        }
        
        if !low.is_empty() {
            html.push_str(&format!("  <h3>LOW: {} issues</h3>\n", low.len()));
            Self::format_vulnerabilities_html(&mut html, &low, "vuln-low");
        }
        
        if !info.is_empty() {
            html.push_str(&format!("  <h3>INFO: {} issues</h3>\n", info.len()));
            Self::format_vulnerabilities_html(&mut html, &info, "vuln-info");
        }
        
        if !error.is_empty() {
            html.push_str(&format!("  <h3>ERROR: {} issues</h3>\n", error.len()));
            Self::format_vulnerabilities_html(&mut html, &error, "vuln-error");
        }
        
        // Configuration
        html.push_str("  <h2>Analysis Configuration</h2>\n");
        html.push_str("  <div class=\"info-box\">\n");
        html.push_str(&format!("    <p><strong>Analyze Constructor:</strong> {}</p>\n", report.analysis_config.analyze_constructor));
        html.push_str(&format!("    <p><strong>Analyze Runtime:</strong> {}</p>\n", report.analysis_config.analyze_runtime));
        html.push_str(&format!("    <p><strong>Max Depth:</strong> {}</p>\n", report.analysis_config.max_depth));
        html.push_str(&format!("    <p><strong>Detect Reentrancy:</strong> {}</p>\n", report.analysis_config.detect_reentrancy));
        html.push_str(&format!("    <p><strong>Detect Arithmetic:</strong> {}</p>\n", report.analysis_config.detect_arithmetic));
        html.push_str(&format!("    <p><strong>Detect Access Control:</strong> {}</p>\n", report.analysis_config.detect_access_control));
        html.push_str(&format!("    <p><strong>Detect Delegate Call:</strong> {}</p>\n", report.analysis_config.detect_delegate_call));
        html.push_str("  </div>\n");
        
        // HTML footer
        html.push_str("</body>\n");
        html.push_str("</html>\n");
        
        html
    }
    
    /// Format vulnerabilities for HTML output
    fn format_vulnerabilities_html(html: &mut String, vulnerabilities: &[&Vulnerability], class: &str) {
        for vuln in vulnerabilities {
            html.push_str(&format!("<div class=\"vulnerability {}\">\n", class));
            html.push_str(&format!("  <h3>{}</h3>\n", vuln.title));
            html.push_str(&format!("  <p><strong>Severity:</strong> {:?}</p>\n", vuln.severity));
            html.push_str(&format!("  <p><strong>Type:</strong> {:?}</p>\n", vuln.vulnerability_type));
            html.push_str(&format!("  <p><strong>Description:</strong> {}</p>\n", vuln.description));
            html.push_str(&format!("  <p><strong>Recommendation:</strong> {}</p>\n", vuln.recommendation));
            html.push_str("</div>\n");
        }
    }
}

/// Report format options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// JSON format
    Json,
    
    /// Plain text format
    Text,
    
    /// HTML format
    Html,
}

/// Extension trait for Vec
trait IsEmpty {
    fn is_empty(&self) -> bool;
}

impl<T> IsEmpty for Vec<T> {
    fn is_empty(&self) -> bool {
        self.is_empty()
    }
}
