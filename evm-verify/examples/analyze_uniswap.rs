use evm_verify::bytecode::analyzer::BytecodeAnalyzer;
use evm_verify::report::ReportFormat;
use evm_verify::ethereum::etherscan::EtherscanClient;
use std::path::Path;
use anyhow::Result;
use dotenv::dotenv;
use std::env;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Load environment variables from .env file
    dotenv().ok();
    
    // Get Etherscan API key from environment
    let api_key = env::var("ETHERSCAN_API_KEY")
        .expect("ETHERSCAN_API_KEY not found in environment variables");
    
    // USDT contract address
    let contract_address = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
    
    println!("Fetching bytecode for USDT contract at address: {}", contract_address);
    
    // Create Etherscan client
    let client = EtherscanClient::new(api_key, "mainnet");
    
    // Fetch bytecode
    let bytecode = client.get_contract_bytecode(contract_address).await?;
    
    println!("Analyzing bytecode...");
    
    // Create analyzer with the bytecode
    let mut analyzer = BytecodeAnalyzer::new(bytecode);
    analyzer.set_test_mode(false);
    
    // Analyze bytecode
    let results = analyzer.analyze()?;
    
    println!("Analysis complete. Found {} potential security issues.", results.warnings.len());
    
    // Generate reports in different formats
    println!("Generating reports...");
    
    // Generate and save JSON report
    analyzer.save_report_to_file(
        "USDT".to_string(),
        ReportFormat::Json,
        Path::new("usdt_security_report.json")
    )?;
    println!("JSON report saved to usdt_security_report.json");
    
    // Generate and save Markdown report
    analyzer.save_report_to_file(
        "USDT".to_string(),
        ReportFormat::Markdown,
        Path::new("usdt_security_report.md")
    )?;
    println!("Markdown report saved to usdt_security_report.md");
    
    // Generate and save HTML report
    analyzer.save_report_to_file(
        "USDT".to_string(),
        ReportFormat::Html,
        Path::new("usdt_security_report.html")
    )?;
    println!("HTML report saved to usdt_security_report.html");
    
    // Print summary of findings
    println!("\nSecurity Analysis Summary:");
    println!("==========================");
    
    if results.warnings.is_empty() {
        println!("No security issues detected!");
    } else {
        for (i, warning) in results.warnings.iter().enumerate() {
            println!("{}. {} (Severity: {})", 
                i + 1, 
                warning, 
                warning
            );
        }
    }
    
    println!("\nDone!");
    
    Ok(())
}
