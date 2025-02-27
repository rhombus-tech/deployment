use evm_verify::bytecode::analyzer::BytecodeAnalyzer;
use evm_verify::report::ReportFormat;
use evm_verify::ethereum::etherscan::EtherscanClient;
use std::path::Path;
use std::env;
use anyhow::Result;

/// This example demonstrates how to analyze a contract with known vulnerabilities
/// It retrieves the bytecode from Etherscan and performs a comprehensive security analysis
#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables from .env file
    dotenv::dotenv().ok();
    
    // Get Etherscan API key from environment
    let api_key = env::var("ETHERSCAN_API_KEY")
        .expect("ETHERSCAN_API_KEY must be set in the environment or .env file");
    
    println!("Starting analysis of a vulnerable contract...");
    
    // Create Etherscan client
    let client = EtherscanClient::new(api_key, "mainnet");
    
    // Contract address for a known contract
    // This is the USDT token contract address
    let contract_address = "0xdac17f958d2ee523a2206206994597c13d831ec7";
    
    println!("Retrieving bytecode for contract at address: {}", contract_address);
    
    // Retrieve bytecode from Etherscan
    let bytecode = client.get_contract_bytecode(contract_address).await?;
    
    println!("Successfully retrieved bytecode ({} bytes)", bytecode.len());
    println!("Starting comprehensive security analysis...");
    
    // Create analyzer with the bytecode
    let mut analyzer = BytecodeAnalyzer::new(bytecode);
    
    // Disable test mode to get full analysis
    analyzer.set_test_mode(false);
    
    // Analyze bytecode
    let results = analyzer.analyze()?;
    
    println!("\nAnalysis complete!");
    println!("Found {} potential security issues.", results.warnings.len());
    println!("Memory accesses: {}", results.memory_accesses.len());
    println!("Storage accesses: {}", results.storage.len());
    
    // Generate reports in different formats
    println!("\nGenerating comprehensive security reports...");
    
    // Generate and save JSON report
    analyzer.save_report_to_file(
        "VulnerableContractAnalysis".to_string(),
        ReportFormat::Json,
        Path::new("vulnerable_contract_report.json")
    )?;
    println!("JSON report saved to vulnerable_contract_report.json");
    
    // Generate and save Markdown report
    analyzer.save_report_to_file(
        "VulnerableContractAnalysis".to_string(),
        ReportFormat::Markdown,
        Path::new("vulnerable_contract_report.md")
    )?;
    println!("Markdown report saved to vulnerable_contract_report.md");
    
    // Generate and save HTML report
    analyzer.save_report_to_file(
        "VulnerableContractAnalysis".to_string(),
        ReportFormat::Html,
        Path::new("vulnerable_contract_report.html")
    )?;
    println!("HTML report saved to vulnerable_contract_report.html");
    
    // Print summary of findings
    println!("\nSecurity Analysis Summary:");
    println!("==========================");
    for (i, warning) in results.warnings.iter().enumerate() {
        println!("{}. {}", i + 1, warning);
    }
    
    println!("\nDone!");
    
    Ok(())
}
