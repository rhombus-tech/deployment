use evm_verify::bytecode::analyzer::BytecodeAnalyzer;
use evm_verify::report::ReportFormat;
use std::path::Path;
use anyhow::Result;

/// This example demonstrates a comprehensive analysis of a bytecode sample
/// that exercises many of the EVM opcodes supported by the analyzer
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Sample bytecode that includes various EVM operations
    // This bytecode includes arithmetic, bitwise, storage, and control flow operations
    let bytecode = "0x608060405234801561001057600080fd5b50610150806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80632e64cec11461003b5780636057361d14610059575b600080fd5b610043610075565b60405161005091906100d9565b60405180910390f35b610073600480360381019061006e919061009d565b61007e565b005b60008054905090565b8060008190555050565b60008135905061009781610103565b92915050565b6000602082840312156100b3576100b26100fe565b5b60006100c184828501610088565b91505092915050565b6100d3816100f4565b82525050565b60006020820190506100ee60008301846100ca565b92915050565b6000819050919050565b600080fd5b61010c816100f4565b811461011757600080fd5b5056fea2646970667358221220223b453ce37f2754e0d5c10dda7e00d2e9e8c7177a31c9f846ce0d33b1f2f8d264736f6c63430008070033".to_string();
    
    println!("Starting comprehensive bytecode analysis...");
    println!("This analysis will exercise many of the supported EVM opcodes:");
    println!("- Arithmetic operations (ADD, SUB, MUL, DIV)");
    println!("- Bitwise operations (AND, OR, XOR)");
    println!("- Comparison operations (LT, GT, EQ, ISZERO)");
    println!("- Stack, Memory, Storage operations");
    println!("- Control flow operations (JUMP, JUMPI)");
    println!("- Environmental information access");
    
    // Create analyzer with the bytecode
    let mut analyzer = BytecodeAnalyzer::new(bytecode.parse()?);
    
    // Disable test mode to get full analysis
    analyzer.set_test_mode(false);
    
    // Analyze bytecode
    let results = analyzer.analyze()?;
    
    println!("\nAnalysis complete!");
    println!("Found {} potential security issues.", results.warnings.len());
    println!("Memory accesses: {}", results.memory_accesses.len());
    println!("Storage accesses: {}", results.storage.len());
    
    // Generate reports in different formats
    println!("\nGenerating comprehensive reports...");
    
    // Generate and save JSON report
    analyzer.save_report_to_file(
        "ComprehensiveAnalysis".to_string(),
        ReportFormat::Json,
        Path::new("comprehensive_report.json")
    )?;
    println!("JSON report saved to comprehensive_report.json");
    
    // Generate and save Markdown report
    analyzer.save_report_to_file(
        "ComprehensiveAnalysis".to_string(),
        ReportFormat::Markdown,
        Path::new("comprehensive_report.md")
    )?;
    println!("Markdown report saved to comprehensive_report.md");
    
    // Generate and save HTML report
    analyzer.save_report_to_file(
        "ComprehensiveAnalysis".to_string(),
        ReportFormat::Html,
        Path::new("comprehensive_report.html")
    )?;
    println!("HTML report saved to comprehensive_report.html");
    
    // Print summary of findings
    println!("\nSecurity Analysis Summary:");
    println!("==========================");
    for (i, warning) in results.warnings.iter().enumerate() {
        println!("{}. {}", i + 1, warning);
    }
    
    println!("\nDone!");
    
    Ok(())
}
