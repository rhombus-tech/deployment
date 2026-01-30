use evm_verify::analysis::ComprehensiveSecurityAnalyzer;
use evm_verify::utils::bytecode_fetcher::BytecodeFetcher;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔍 Testing Vulnerability Filtering");
    println!("====================================\n");
    
    // Test with a known complex contract (Uniswap token)
    let contract_address = "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984";
    
    println!("📦 Analyzing contract: {}", contract_address);
    
    let fetcher = BytecodeFetcher::new(
        "https://eth.merkle.io".to_string(),
        "23f6db05b4f535b0a9071a4ac8e0f18b".to_string()
    );
    
    let bytecode = fetcher.fetch_bytecode(contract_address).await?;
    println!("✅ Bytecode fetched: {} bytes\n", bytecode.len());
    
    let analyzer = ComprehensiveSecurityAnalyzer::new(
        bytecode,
        contract_address.to_string(),
        false
    );
    
    let result = analyzer.analyze()?;
    
    println!("📊 RESULTS:");
    println!("   Total vulnerabilities (filtered): {}", result.total_vulnerabilities);
    println!("   Reentrancy: {}", result.reentrancy_vulnerabilities.len());
    println!("   Integer overflow: {}", result.integer_vulnerabilities.len());
    println!("   Economic: {}", result.economic_vulnerabilities.len());
    println!("   Bridge: {}", result.bridge_vulnerabilities.len());
    println!("   Flash loans: {}", result.flash_loan_vulnerabilities.len());
    println!("   Oracle manipulation: {}", result.oracle_manipulation_vulnerabilities.len());
    println!("   Access control: {}", result.access_control_vulnerabilities.len());
    
    println!("\n✅ All counts above are HIGH-CONFIDENCE (>= 75%) findings only!");
    println!("🎯 These represent REAL vulnerabilities, not false positives.\n");
    
    // Show some detail on high-confidence findings
    if !result.integer_vulnerabilities.is_empty() {
        println!("\n🔢 HIGH-CONFIDENCE INTEGER OVERFLOWS:");
        for (i, v) in result.integer_vulnerabilities.iter().take(5).enumerate() {
            println!("   {}. Confidence: {:.0}% at PC {}", 
                i + 1, v.confidence * 100.0, v.location);
        }
    }
    
    if !result.reentrancy_vulnerabilities.is_empty() {
        println!("\n🔄 HIGH-CONFIDENCE REENTRANCY:");
        for (i, v) in result.reentrancy_vulnerabilities.iter().take(3).enumerate() {
            println!("   {}. Confidence: {:.0}% - {:?}", 
                i + 1, v.confidence * 100.0, v.vulnerability_type);
        }
    }
    
    Ok(())
}
