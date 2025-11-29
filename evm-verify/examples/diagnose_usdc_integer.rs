// Quick diagnostic for USDC integer issues
use ethers::providers::{Provider, Http, Middleware};
use ethers::types::{Address, Bytes};
use std::str::FromStr;
use evm_verify::analysis::comprehensive_analyzer::ComprehensiveSecurityAnalyzer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = std::env::var("ETH_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:8545".to_string());
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    // Change to BeautyChain to debug
    let usdc = Address::from_str("0xc5d105e63711398af9bbff092d4b6769c82f793d")?;
    let code: Bytes = provider.get_code(usdc, None).await?;
    
    let analyzer = ComprehensiveSecurityAnalyzer::new(code.to_vec());
    let result = analyzer.analyze();
    
    // Check SafeMath detection
    use evm_verify::analysis::integer_safety_detector::IntegerSafetyDetector;
    let int_detector = IntegerSafetyDetector::new(code.to_vec());
    
    println!("BeautyChain Integer Issues:");
    println!("Total: {}", result.integer_vulnerabilities.len());
    
    // Check for MUL operations specifically (batchOverflow was a MUL bug)
    let mul_ops: Vec<_> = result.integer_vulnerabilities.iter()
        .filter(|v| matches!(v.operation, evm_verify::analysis::integer_safety_detector::ArithmeticOp::Multiplication))
        .collect();
    println!("MUL operations: {}", mul_ops.len());
    for (i, v) in mul_ops.iter().take(5).enumerate() {
        println!("  {}. PC: {}, Conf: {:.0}%, Sev: {:?}",
                 i+1, v.pc, v.confidence * 100.0, v.severity);
    }
    
    // Check for any that meet the threshold: (Critical AND >80%) OR (High AND >85%) OR (>95%)
    let meets_threshold: Vec<_> = result.integer_vulnerabilities.iter()
        .filter(|v| {
            (matches!(v.severity, evm_verify::bytecode::SecuritySeverity::Critical) && v.confidence > 0.80) ||
            (matches!(v.severity, evm_verify::bytecode::SecuritySeverity::High) && v.confidence > 0.85) ||
            v.confidence > 0.95
        })
        .collect();
    
    println!("\nMeets threshold (would be flagged): {}", meets_threshold.len());
    for (i, v) in meets_threshold.iter().take(10).enumerate() {
        println!("  {}. PC: {}, Op: {:?}, Conf: {:.0}%, Sev: {:?}",
                 i+1, v.pc, v.operation, v.confidence * 100.0, v.severity);
    }
    
    Ok(())
}
