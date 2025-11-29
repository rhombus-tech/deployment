// Test conservative analyzer accuracy
// Usage: cargo run --example test_conservative_accuracy

use ethers::providers::{Provider, Http, Middleware};
use ethers::types::{Address, Bytes};
use std::str::FromStr;
use evm_verify::analysis::conservative_config::analyze_conservative;

#[derive(Debug)]
struct TestContract {
    name: &'static str,
    address: &'static str,
    expected_vulnerable: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔬 CONSERVATIVE ANALYZER TEST");
    println!("==============================\n");
    
    let rpc_url = std::env::var("ETH_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:8545".to_string());
    
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    let test_contracts = vec![
        // Known vulnerable
        TestContract {
            name: "The DAO (Reentrancy)",
            address: "0xbb9bc244d798123fde783fcc1c72d3bb8c189413",
            expected_vulnerable: true,
        },
        TestContract {
            name: "BeautyChain (Integer Overflow)",
            address: "0xc5d105e63711398af9bbff092d4b6769c82f793d",
            expected_vulnerable: true,
        },
        // Known safe
        TestContract {
            name: "USDC Token",
            address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            expected_vulnerable: false,
        },
        TestContract {
            name: "Uniswap V2 Router",
            address: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
            expected_vulnerable: false,
        },
        TestContract {
            name: "Compound cDAI",
            address: "0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643",
            expected_vulnerable: false,
        },
    ];
    
    println!("Testing {} contracts with CONSERVATIVE settings...\n", test_contracts.len());
    
    let mut true_positives = 0;
    let mut true_negatives = 0;
    let mut false_positives = 0;
    let mut false_negatives = 0;
    
    for (i, test) in test_contracts.iter().enumerate() {
        println!("[{}/{}] Testing: {}", i + 1, test_contracts.len(), test.name);
        
        let addr = Address::from_str(test.address)?;
        let code: Bytes = provider.get_code(addr, None).await?;
        
        if code.is_empty() {
            println!("         ⚠️  No bytecode\n");
            continue;
        }
        
        // Analyze with CONSERVATIVE settings
        let result = analyze_conservative(&code.to_vec());
        
        let has_vulns = result.total_vulnerabilities > 0;
        
        println!("         Total vulns: {}", result.total_vulnerabilities);
        println!("         Critical: {}", result.critical_count);
        println!("         High: {}", result.high_count);
        
        // Determine result
        match (test.expected_vulnerable, has_vulns) {
            (true, true) => {
                true_positives += 1;
                println!("         ✅ TRUE POSITIVE\n");
            }
            (false, false) => {
                true_negatives += 1;
                println!("         ✅ TRUE NEGATIVE\n");
            }
            (false, true) => {
                false_positives += 1;
                println!("         ❌ FALSE POSITIVE\n");
            }
            (true, false) => {
                false_negatives += 1;
                println!("         ❌ FALSE NEGATIVE\n");
            }
        }
        
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }
    
    // Print report
    let total = true_positives + true_negatives + false_positives + false_negatives;
    let accuracy = ((true_positives + true_negatives) as f64 / total as f64) * 100.0;
    let fp_rate = if true_negatives + false_positives > 0 {
        (false_positives as f64 / (true_negatives + false_positives) as f64) * 100.0
    } else {
        0.0
    };
    let detection_rate = if true_positives + false_negatives > 0 {
        (true_positives as f64 / (true_positives + false_negatives) as f64) * 100.0
    } else {
        0.0
    };
    
    println!("\n📊 CONSERVATIVE ANALYZER RESULTS");
    println!("=================================\n");
    println!("Accuracy: {:.1}%", accuracy);
    println!("Detection Rate: {:.1}%", detection_rate);
    println!("False Positive Rate: {:.1}%", fp_rate);
    println!();
    println!("True Positives: {}", true_positives);
    println!("True Negatives: {}", true_negatives);
    println!("False Positives: {}", false_positives);
    println!("False Negatives: {}", false_negatives);
    
    println!("\n🎯 ASSESSMENT:");
    if fp_rate <= 5.0 && detection_rate >= 80.0 {
        println!("✅ PASS - Ready for production");
    } else {
        println!("❌ FAIL - Needs more tuning");
        if fp_rate > 5.0 {
            println!("   FP rate: {:.1}% (target: ≤5%)", fp_rate);
        }
        if detection_rate < 80.0 {
            println!("   Detection: {:.1}% (target: ≥80%)", detection_rate);
        }
    }
    
    Ok(())
}
