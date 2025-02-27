// EVM Verify CLI
//
// This is the command-line interface for the EVM Verify tool.

use anyhow::{Result, Context};
use clap::{Parser, Subcommand};
use evm_verify::api::{EVMVerify, AnalysisConfig, ConfigManager, ReportFormat, ReportFormatter};
use std::path::PathBuf;
use std::fs;

/// EVM Verify - Ethereum Smart Contract Security Analyzer
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a smart contract
    Analyze {
        /// Path to the bytecode file or hex string
        #[clap(short, long)]
        input: String,
        
        /// Output format (json, text, html)
        #[clap(short, long, default_value = "text")]
        format: String,
        
        /// Output file path
        #[clap(short, long)]
        output: Option<PathBuf>,
        
        /// Path to configuration file
        #[clap(short, long)]
        config: Option<PathBuf>,
    },
    
    /// Generate a default configuration file
    Config {
        /// Output file path
        #[clap(short, long)]
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Analyze { input, format, output, config } => {
            // Load configuration if provided
            let analyzer = if let Some(config_path) = config {
                let config = ConfigManager::load_from_file(&config_path)
                    .context("Failed to load configuration")?;
                EVMVerify::with_config(config)
            } else {
                EVMVerify::new()
            };
            
            // Determine if input is a file or hex string
            let bytecode_str = if input.starts_with("0x") || input.chars().all(|c| c.is_ascii_hexdigit()) {
                input
            } else {
                // Assume it's a file path
                fs::read_to_string(&input)
                    .context("Failed to read bytecode file")?
                    .trim()
                    .to_string()
            };
            
            // Analyze the bytecode
            let report = analyzer.analyze_from_hex(&bytecode_str)
                .context("Failed to analyze bytecode")?;
            
            // Determine report format
            let report_format = match format.to_lowercase().as_str() {
                "json" => ReportFormat::Json,
                "html" => ReportFormat::Html,
                _ => ReportFormat::Text,
            };
            
            // Generate and output the report
            if let Some(output_path) = output {
                ReportFormatter::save_to_file(&report, &output_path, report_format)
                    .context("Failed to save report")?;
                println!("Report saved to {:?}", output_path);
            } else {
                // Print to stdout
                let report_str = match report_format {
                    ReportFormat::Json => ReportFormatter::to_json(&report)?,
                    ReportFormat::Text => ReportFormatter::to_text(&report),
                    ReportFormat::Html => ReportFormatter::to_html(&report),
                };
                println!("{}", report_str);
            }
            
            Ok(())
        },
        Commands::Config { output } => {
            // Generate default configuration
            let config = AnalysisConfig::default();
            ConfigManager::save_to_file(&config, &output)
                .context("Failed to save configuration")?;
            println!("Default configuration saved to {:?}", output);
            Ok(())
        },
    }
}
