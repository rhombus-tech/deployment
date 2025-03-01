// Chain-specific Contract Analyzer CLI
//
// This binary provides a command-line interface for analyzing smart contracts
// on different EVM-compatible chains.

use anyhow::Result;
use clap::{Parser, Subcommand};
use ethers::types::Address;
use std::str::FromStr;
use evm_verify::ethereum::{EthereumConnector, chain::ChainRegistry};
use evm_verify::api::{EVMVerify, AnalysisConfig, ReportFormat};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a smart contract on a specific chain
    Analyze {
        /// Contract address to analyze
        #[clap(long, short)]
        address: String,
        
        /// RPC URL for the chain
        #[clap(long, short)]
        rpc_url: String,
        
        /// Output format (text, json, html)
        #[clap(long, short, default_value = "text")]
        format: String,
        
        /// Output file (optional)
        #[clap(long, short)]
        output: Option<String>,
    },
    
    /// List supported chains
    ListChains,
}

fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();
    
    // Parse command line arguments
    let cli = Cli::parse();
    
    match &cli.command {
        Commands::Analyze { address, rpc_url, format, output } => {
            // Parse contract address
            let contract_address = Address::from_str(address)
                .map_err(|_| anyhow::anyhow!("Invalid contract address"))?;
            
            // Create Ethereum connector
            let mut connector = EthereumConnector::new(rpc_url)?;
            
            // Initialize connector and get chain ID
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                connector.init().await?;
                let chain_id = connector.chain_id().await?;
                let chain_config = connector.chain_config().await?;
                
                println!("Analyzing contract {} on {} (Chain ID: {})", 
                         address, chain_config.name, chain_id);
                
                // Analyze contract and get results
                let _results = connector.analyze_contract(contract_address).await?;
                
                // Get the raw bytecode for the report
                let bytecode = connector.get_bytecode(contract_address).await?;
                
                // Create report
                let evm_verify = EVMVerify::with_config(AnalysisConfig {
                    analyze_constructor: true,
                    analyze_runtime: true,
                    max_depth: 1000,
                    detect_reentrancy: true,
                    detect_arithmetic: true,
                    detect_access_control: true,
                    detect_delegate_call: true,
                    detect_flash_loan: true,
                    detect_oracle_manipulation: true,
                    detect_governance: true,
                });
                
                // Create a public method to generate a report
                let report = evm_verify.analyze_bytecode(ethers::types::Bytes::from(bytecode))?;
                
                // Determine output format
                let report_format = match format.to_lowercase().as_str() {
                    "json" => ReportFormat::Json,
                    "html" => ReportFormat::Html,
                    _ => ReportFormat::Text,
                };
                
                // Format report
                let formatted_report = match report_format {
                    ReportFormat::Json => evm_verify::api::ReportFormatter::to_json(&report)?,
                    ReportFormat::Html => evm_verify::api::ReportFormatter::to_html(&report),
                    ReportFormat::Text => evm_verify::api::ReportFormatter::to_text(&report),
                };
                
                // Output report
                if let Some(output_path) = output {
                    evm_verify::api::ReportFormatter::save_to_file(&report, output_path, report_format)?;
                    println!("Report saved to {}", output_path);
                } else {
                    println!("{}", formatted_report);
                }
                
                Ok::<_, anyhow::Error>(())
            })?;
        },
        Commands::ListChains => {
            // Create chain registry
            let registry = ChainRegistry::new();
            
            println!("Supported chains:");
            println!("----------------");
            
            // List Ethereum Mainnet
            let eth_config = registry.get_config(1).unwrap();
            println!("- {} (Chain ID: {})", eth_config.name, eth_config.chain_id);
            println!("  Block Time: {} seconds", eth_config.block_time);
            println!("  Currency: {}", eth_config.currency_symbol);
            println!("  Security Considerations:");
            for consideration in &eth_config.security_considerations {
                println!("    * {}", consideration);
            }
            println!();
            
            // List Polygon
            let polygon_config = registry.get_config(137).unwrap();
            println!("- {} (Chain ID: {})", polygon_config.name, polygon_config.chain_id);
            println!("  Block Time: {} seconds", polygon_config.block_time);
            println!("  Currency: {}", polygon_config.currency_symbol);
            println!("  Security Considerations:");
            for consideration in &polygon_config.security_considerations {
                println!("    * {}", consideration);
            }
            println!();
            
            // List other supported chains
            for chain_id in &[56, 42161, 10, 43114] {
                if let Some(config) = registry.get_config(*chain_id) {
                    println!("- {} (Chain ID: {})", config.name, config.chain_id);
                    println!("  Block Time: {} seconds", config.block_time);
                    println!("  Currency: {}", config.currency_symbol);
                    println!("  Security Considerations:");
                    for consideration in &config.security_considerations {
                        println!("    * {}", consideration);
                    }
                    println!();
                }
            }
        }
    }
    
    Ok(())
}
