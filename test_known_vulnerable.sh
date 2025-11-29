#!/bin/bash
# Test if we still detect the known vulnerable contract

cd /Users/talzisckind/Downloads/deployment/evm-verify

echo "Testing known vulnerable contract: 0x0e87bF5286C4091e0eeb7814D802115dFBb4c4cd"
echo ""

# Create a test that scans this specific contract
cat > examples/test_single_contract.rs << 'EOF'
use ethers::providers::{Provider, Http, Middleware};
use std::str::FromStr;
use evm_verify::analysis::comprehensive_analyzer::{ComprehensiveSecurityAnalyzer, ComprehensiveAnalysisResult};
use ethers::types::Address;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc = "https://ethereum.publicnode.com";
    let provider = Provider::<Http>::try_from(rpc)?;
    
    // Known vulnerable contract
    let addr = Address::from_str("0x0e87bF5286C4091e0eeb7814D802115dFBb4c4cd")?;
    
    println!("Fetching bytecode for: {:?}", addr);
    let code = provider.get_code(addr, None).await?;
    
    println!("Bytecode size: {} bytes", code.len());
    println!("Running comprehensive analysis...\n");
    
    let analyzer = ComprehensiveSecurityAnalyzer::new(code.to_vec());
    let result = analyzer.analyze();
    
    println!("BEFORE FILTERING:");
    println!("  Total vulnerabilities: {}", result.total_vulnerabilities);
    println!("  Reentrancy: {}", result.reentrancy_vulnerabilities.len());
    println!("  Integer: {}", result.integer_vulnerabilities.len());
    println!("  Economic: {}", result.economic_vulnerabilities.len());
    
    Ok(())
}
EOF

cargo run --example test_single_contract
