use anyhow::{Result, Context};
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;
use std::fs;
use serde_json;
use super::{DeploymentGateway, GatewaySettings, create_default_gateway, Severity};

/// Command-line interface for AI Agent Security Gateway
#[derive(Parser)]
#[clap(name = "ai-security-gateway")]
#[clap(about = "Security verification for AI-generated smart contracts and agent actions")]
pub struct Cli {
    /// Subcommands for the gateway
    #[clap(subcommand)]
    command: Commands,
    
    /// Allow contracts with critical vulnerabilities to pass verification
    #[clap(long, global = true)]
    allow_critical: bool,
    
    /// Minimum severity level to report (info, warning, critical)
    #[clap(long, global = true, default_value = "info")]
    min_severity: String,
    
    /// Skip report generation
    #[clap(long, global = true)]
    skip_report: bool,
    
    /// Enable analysis of action sequences
    #[clap(long, global = true)]
    analyze_sequences: bool,
}

/// Subcommands for the gateway
#[derive(Subcommand)]
enum Commands {
    /// Verify a smart contract bytecode file
    Verify {
        /// Path to contract bytecode file
        #[clap(short, long)]
        file: PathBuf,
        
        /// Output file for report (default: print to stdout)
        #[clap(short, long)]
        output: Option<PathBuf>,
        
        /// Output format (text or json)
        #[clap(long, default_value = "text")]
        format: String,
    },
    
    /// Verify a sequence of agent actions
    VerifySequence {
        /// Paths to action bytecode files
        #[clap(short, long)]
        files: Vec<PathBuf>,
        
        /// Output file for report (default: print to stdout)
        #[clap(short, long)]
        output: Option<PathBuf>,
        
        /// Output format (text or json)
        #[clap(long, default_value = "text")]
        format: String,
    },
}

/// Run the CLI application
pub fn run_cli() -> Result<()> {
    // Parse command-line arguments
    let cli = Cli::parse();
    
    // Create gateway settings from CLI options
    let settings = GatewaySettings {
        allow_critical_warnings: cli.allow_critical,
        min_severity: parse_severity_level(&cli.min_severity)?,
        generate_reports: !cli.skip_report,
        analyze_action_sequences: cli.analyze_sequences,
    };
    
    // Create gateway with default detectors
    let gateway = create_default_gateway(Some(settings))
        .context("Failed to create security gateway")?;
    
    // Execute subcommand
    match cli.command {
        Commands::Verify { file, output, format } => {
            verify_contract(&gateway, file, output, &format)?;
        }
        Commands::VerifySequence { files, output, format } => {
            verify_sequence(&gateway, files, output, &format)?;
        }
    }
    
    Ok(())
}

/// Parse severity level from string
fn parse_severity_level(level: &str) -> Result<Severity> {
    match level.to_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "warning" => Ok(Severity::Warning),
        "critical" => Ok(Severity::Critical),
        _ => Err(anyhow::anyhow!("Invalid severity level: {}. Use 'info', 'warning', or 'critical'", level)),
    }
}

/// Verify a smart contract
fn verify_contract(
    gateway: &DeploymentGateway,
    file_path: PathBuf,
    output_path: Option<PathBuf>,
    format: &str
) -> Result<()> {
    // Read bytecode file
    println!("{} {}...", "Reading".blue().bold(), file_path.display());
    let bytecode = fs::read(&file_path)
        .with_context(|| format!("Failed to read bytecode from {}", file_path.display()))?;
    
    // Verify contract
    println!("{} security verification...", "Running".blue().bold());
    let result = gateway.verify_contract(&bytecode)
        .context("Failed to verify contract")?;
    
    // Generate report
    if let Some(report) = &result.report {
        let formatted_report = match format.to_lowercase().as_str() {
            "json" => serde_json::to_string_pretty(report)?,
            _ => gateway.report_generator.format_report_text(report),
        };
        
        // Output report
        match &output_path {
            Some(path) => {
                fs::write(path, formatted_report)
                    .with_context(|| format!("Failed to write report to {}", path.display()))?;
                println!("{} written to {}", "Report".green().bold(), path.display());
            }
            None => {
                println!("\n{}\n", formatted_report);
            }
        }
    }
    
    // Print summary to console
    print_verification_summary(&result);
    
    Ok(())
}

/// Verify a sequence of agent actions
fn verify_sequence(
    gateway: &DeploymentGateway,
    file_paths: Vec<PathBuf>,
    output_path: Option<PathBuf>,
    format: &str
) -> Result<()> {
    if !gateway.settings.analyze_action_sequences {
        return Err(anyhow::anyhow!("Action sequence analysis is disabled. Enable with --analyze-sequences"));
    }
    
    // Read all action bytecode files
    println!("{} {} action files...", "Reading".blue().bold(), file_paths.len());
    let mut actions = Vec::new();
    
    for path in &file_paths {
        let bytecode = fs::read(path)
            .with_context(|| format!("Failed to read bytecode from {}", path.display()))?;
        actions.push(bytecode);
    }
    
    // Verify sequence
    println!("{} sequence verification...", "Running".blue().bold());
    let result = gateway.verify_action_sequence(&actions)
        .context("Failed to verify action sequence")?;
    
    // Generate report
    if let Some(report) = &result.report {
        let formatted_report = match format.to_lowercase().as_str() {
            "json" => serde_json::to_string_pretty(report)?,
            _ => gateway.report_generator.format_report_text(report),
        };
        
        // Output report
        match &output_path {
            Some(path) => {
                fs::write(path, formatted_report)
                    .with_context(|| format!("Failed to write report to {}", path.display()))?;
                println!("{} written to {}", "Report".green().bold(), path.display());
            }
            None => {
                println!("\n{}\n", formatted_report);
            }
        }
    }
    
    // Print summary to console
    print_verification_summary(&result);
    
    Ok(())
}

/// Print verification result summary
fn print_verification_summary(result: &super::VerificationResult) {
    println!("\n=== {} ===\n", "Verification Summary".yellow().bold());
    
    let critical = result.warnings.iter().filter(|w| w.severity == Severity::Critical).count();
    let warnings = result.warnings.iter().filter(|w| w.severity == Severity::Warning).count();
    let info = result.warnings.iter().filter(|w| w.severity == Severity::Info).count();
    
    println!("Critical issues: {}", if critical > 0 { critical.to_string().red().bold() } else { critical.to_string().green() });
    println!("Warnings: {}", if warnings > 0 { warnings.to_string().yellow() } else { warnings.to_string().green() });
    println!("Info: {}", info);
    
    if result.passed {
        println!("\n{}", "✓ Verification PASSED".green().bold());
    } else {
        println!("\n{}", "✗ Verification FAILED".red().bold());
    }
}
