// Run accuracy tests on analyzers
// Usage: cargo run --example test_analyzer_accuracy

use ethers::providers::{Provider, Http, Middleware};
use ethers::types::{Address, Bytes};
use std::str::FromStr;
use evm_verify::analysis::comprehensive_analyzer::ComprehensiveSecurityAnalyzer;

#[derive(Debug)]
struct TestContract {
    name: &'static str,
    address: &'static str,
    expected_vulnerable: bool,
    expected_vulns: Vec<&'static str>,
}

struct AccuracyReport {
    total_tested: usize,
    true_positives: usize,
    true_negatives: usize,
    false_positives: usize,
    false_negatives: usize,
    vulnerable_contracts: Vec<ContractReport>,
    safe_contracts: Vec<ContractReport>,
}

struct ContractReport {
    name: String,
    address: String,
    expected_vulns: Vec<String>,
    detected_vulns: Vec<String>,
    result: TestResult,
}

#[derive(Debug, Clone, Copy)]
enum TestResult {
    TruePositive,
    TrueNegative,
    FalsePositive,
    FalseNegative,
}

impl AccuracyReport {
    fn new() -> Self {
        Self {
            total_tested: 0,
            true_positives: 0,
            true_negatives: 0,
            false_positives: 0,
            false_negatives: 0,
            vulnerable_contracts: vec![],
            safe_contracts: vec![],
        }
    }
    
    fn detection_rate(&self) -> f64 {
        if self.true_positives + self.false_negatives == 0 {
            return 0.0;
        }
        (self.true_positives as f64 / (self.true_positives + self.false_negatives) as f64) * 100.0
    }
    
    fn false_positive_rate(&self) -> f64 {
        if self.true_negatives + self.false_positives == 0 {
            return 0.0;
        }
        (self.false_positives as f64 / (self.true_negatives + self.false_positives) as f64) * 100.0
    }
    
    fn accuracy(&self) -> f64 {
        if self.total_tested == 0 {
            return 0.0;
        }
        ((self.true_positives + self.true_negatives) as f64 / self.total_tested as f64) * 100.0
    }
}

fn get_test_contracts() -> Vec<TestContract> {
    vec![
        // ========== KNOWN VULNERABLE CONTRACTS ==========
        
        // The DAO - Reentrancy
        TestContract {
            name: "The DAO (Reentrancy)",
            address: "0xbb9bc244d798123fde783fcc1c72d3bb8c189413",
            expected_vulnerable: true,
            expected_vulns: vec!["reentrancy"],
        },
        
        // BeautyChain - Integer Overflow
        TestContract {
            name: "BeautyChain (Integer Overflow)",
            address: "0xc5d105e63711398af9bbff092d4b6769c82f793d",
            expected_vulnerable: true,
            expected_vulns: vec!["integer_overflow"],
        },
        
        // ========== KNOWN SAFE CONTRACTS ==========
        
        // USDC - Well audited stablecoin
        TestContract {
            name: "USDC Token",
            address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            expected_vulnerable: false,
            expected_vulns: vec![],
        },
        
        // Uniswap V2 Router - Battle tested
        TestContract {
            name: "Uniswap V2 Router",
            address: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
            expected_vulnerable: false,
            expected_vulns: vec![],
        },
        
        // Compound cDAI - Audited
        TestContract {
            name: "Compound cDAI",
            address: "0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643",
            expected_vulnerable: false,
            expected_vulns: vec![],
        },
    ]
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔬 ANALYZER ACCURACY TEST");
    println!("==========================\n");
    
    // Setup
    let rpc_url = std::env::var("ETH_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:8545".to_string());
    
    let provider = Provider::<Http>::try_from(rpc_url)?;
    let test_contracts = get_test_contracts();
    
    println!("Testing {} contracts...\n", test_contracts.len());
    
    let mut report = AccuracyReport::new();
    
    for (i, test) in test_contracts.iter().enumerate() {
        println!("[{}/{}] Testing: {}", i + 1, test_contracts.len(), test.name);
        println!("         Address: {}", test.address);
        
        // Fetch bytecode
        let addr = Address::from_str(test.address)?;
        let code: Bytes = provider.get_code(addr, None).await?;
        
        if code.is_empty() {
            println!("         ⚠️  No bytecode (not a contract)\n");
            continue;
        }
        
        // Analyze
        let bytecode = code.to_vec();
        let analyzer = ComprehensiveSecurityAnalyzer::new(bytecode.clone());
        let result = analyzer.analyze();
        
        let has_vulns = result.total_vulnerabilities > 0;
        let detected_types: Vec<String> = vec![
            format!("Total: {} vulnerabilities", result.total_vulnerabilities),
            format!("Critical: {}", result.security_summary.critical_count),
            format!("High: {}", result.security_summary.high_count),
        ];
        
        // Determine result
        let result = match (test.expected_vulnerable, has_vulns) {
            (true, true) => {
                report.true_positives += 1;
                TestResult::TruePositive
            }
            (false, false) => {
                report.true_negatives += 1;
                TestResult::TrueNegative
            }
            (false, true) => {
                report.false_positives += 1;
                TestResult::FalsePositive
            }
            (true, false) => {
                report.false_negatives += 1;
                TestResult::FalseNegative
            }
        };
        
        report.total_tested += 1;
        
        let contract_report = ContractReport {
            name: test.name.to_string(),
            address: test.address.to_string(),
            expected_vulns: test.expected_vulns.iter().map(|s| s.to_string()).collect(),
            detected_vulns: detected_types.clone(),
            result,
        };
        
        if test.expected_vulnerable {
            report.vulnerable_contracts.push(contract_report);
        } else {
            report.safe_contracts.push(contract_report);
        }
        
        // Print result
        match result {
            TestResult::TruePositive => {
                println!("         ✅ TRUE POSITIVE - Correctly detected vulnerability");
                println!("         Found: {:?}", detected_types);
            }
            TestResult::TrueNegative => {
                println!("         ✅ TRUE NEGATIVE - Correctly identified as safe");
            }
            TestResult::FalsePositive => {
                println!("         ❌ FALSE POSITIVE - Incorrectly flagged as vulnerable!");
                println!("         False alarms: {:?}", detected_types);
            }
            TestResult::FalseNegative => {
                println!("         ❌ FALSE NEGATIVE - Missed known vulnerability!");
                println!("         Expected: {:?}", test.expected_vulns);
            }
        }
        
        println!();
        
        // Rate limit
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }
    
    // Print report
    print_report(&report);
    
    // Determine if analyzers are production-ready
    let fp_rate = report.false_positive_rate();
    let detection_rate = report.detection_rate();
    
    println!("\n🎯 PRODUCTION READINESS ASSESSMENT");
    println!("===================================\n");
    
    if fp_rate <= 5.0 && detection_rate >= 80.0 {
        println!("✅ PASS - Analyzers are production-ready");
        println!("   False positive rate: {:.1}% (threshold: ≤5%)", fp_rate);
        println!("   Detection rate: {:.1}% (threshold: ≥80%)", detection_rate);
    } else {
        println!("❌ FAIL - Analyzers need improvement");
        if fp_rate > 5.0 {
            println!("   ⚠️  False positive rate too high: {:.1}% (threshold: ≤5%)", fp_rate);
        }
        if detection_rate < 80.0 {
            println!("   ⚠️  Detection rate too low: {:.1}% (threshold: ≥80%)", detection_rate);
        }
    }
    
    Ok(())
}

fn print_report(report: &AccuracyReport) {
    println!("\n📊 ACCURACY REPORT");
    println!("==================\n");
    
    println!("Overall Statistics:");
    println!("  Total Tested: {}", report.total_tested);
    println!("  Accuracy: {:.1}%", report.accuracy());
    println!();
    
    println!("Detection Performance:");
    println!("  True Positives: {} (correctly found vulnerabilities)", report.true_positives);
    println!("  False Negatives: {} (missed vulnerabilities)", report.false_negatives);
    println!("  Detection Rate: {:.1}%", report.detection_rate());
    println!();
    
    println!("False Positive Analysis:");
    println!("  True Negatives: {} (correctly identified as safe)", report.true_negatives);
    println!("  False Positives: {} (incorrectly flagged)", report.false_positives);
    println!("  False Positive Rate: {:.1}%", report.false_positive_rate());
    println!();
    
    if report.false_positives > 0 {
        println!("⚠️  FALSE POSITIVES DETAILS:");
        for contract in &report.safe_contracts {
            if matches!(contract.result, TestResult::FalsePositive) {
                println!("  • {} ({})", contract.name, contract.address);
                println!("    Incorrectly detected: {:?}", contract.detected_vulns);
            }
        }
        println!();
    }
    
    if report.false_negatives > 0 {
        println!("⚠️  FALSE NEGATIVES DETAILS:");
        for contract in &report.vulnerable_contracts {
            if matches!(contract.result, TestResult::FalseNegative) {
                println!("  • {} ({})", contract.name, contract.address);
                println!("    Missed: {:?}", contract.expected_vulns);
            }
        }
        println!();
    }
}
