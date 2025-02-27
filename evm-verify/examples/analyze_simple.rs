use evm_verify::bytecode::analyzer::BytecodeAnalyzer;
use evm_verify::report::ReportFormat;
use std::path::Path;
use anyhow::Result;
use ethers::types::Bytes;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Simple storage contract bytecode
    let bytecode_hex = "0x608060405234801561001057600080fd5b50600436106100365760003560e01c80632e64cec11461003b5780636057361d14610059575b600080fd5b610043610075565b60405161005091906100d9565b60405180910390f35b610073600480360381019061006e919061009d565b61007e565b005b60008054905090565b8060008190555050565b60008135905061009781610103565b92915050565b6000602082840312156100b3576100b26100fe565b5b60006100c184828501610088565b91505092915050565b6100d3816100f4565b82525050565b60006020820190506100ee60008301846100ca565b92915050565b6000819050919050565b600080fd5b61010c816100f4565b811461011757600080fd5b5056fea2646970667358221220223a0a4797783b89d0460af3ca4b8a19b4d58b33f50d7bf24a42b7b1c79e3b5564736f6c63430008070033";
    
    // Convert hex string to Bytes
    let bytecode = Bytes::from(hex::decode(&bytecode_hex[2..]).expect("Invalid hex string"));
    
    println!("Analyzing SimpleStorage bytecode...");
    
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
        "SimpleStorage".to_string(),
        ReportFormat::Json,
        Path::new("simple_storage_report.json")
    )?;
    println!("JSON report saved to simple_storage_report.json");
    
    // Generate and save Markdown report
    analyzer.save_report_to_file(
        "SimpleStorage".to_string(),
        ReportFormat::Markdown,
        Path::new("simple_storage_report.md")
    )?;
    println!("Markdown report saved to simple_storage_report.md");
    
    // Generate and save HTML report
    analyzer.save_report_to_file(
        "SimpleStorage".to_string(),
        ReportFormat::Html,
        Path::new("simple_storage_report.html")
    )?;
    println!("HTML report saved to simple_storage_report.html");
    
    // Print summary of findings
    println!("\nSecurity Analysis Summary:");
    println!("==========================");
    
    if results.warnings.is_empty() {
        println!("No security issues detected!");
    } else {
        for (i, warning) in results.warnings.iter().enumerate() {
            println!("{}. {}", i + 1, warning);
        }
    }
    
    println!("\nDone!");
    
    Ok(())
}
