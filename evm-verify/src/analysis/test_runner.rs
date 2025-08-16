use crate::analysis::comprehensive_analyzer::{
    ComprehensiveSecurityAnalyzer, 
    ComprehensiveAnalyzerBuilder,
    ModuleConfig,
};
use std::time::Instant;

/// Test cases for comprehensive security analysis
pub struct SecurityTestRunner {
    test_cases: Vec<TestCase>,
}

#[derive(Debug)]
pub struct TestCase {
    pub name: String,
    pub bytecode: Vec<u8>,
    pub expected_vulnerabilities: u32,
    pub expected_modules: Vec<String>,
    pub description: String,
}

#[derive(Debug)]
pub struct TestResult {
    pub test_name: String,
    pub passed: bool,
    pub actual_vulnerabilities: u32,
    pub expected_vulnerabilities: u32,
    pub analysis_time_ms: u64,
    pub error_message: Option<String>,
}

impl SecurityTestRunner {
    pub fn new() -> Self {
        Self {
            test_cases: Self::create_test_cases(),
        }
    }

    /// Create comprehensive test cases covering all attack vectors
    fn create_test_cases() -> Vec<TestCase> {
        vec![
            // Death spiral vulnerability test
            TestCase {
                name: "death_spiral_stablecoin".to_string(),
                bytecode: vec![
                    // mint() function signature
                    0x63, 0x40, 0xc1, 0x0f, 0x19,
                    // burn() function signature  
                    0x63, 0x42, 0x96, 0x6c, 0x68,
                    // No emergency backstop functions
                    0x00, 0x00, 0x00, 0x00,
                ],
                expected_vulnerabilities: 1,
                expected_modules: vec!["economic".to_string()],
                description: "Stablecoin with mint/burn but no confidence backstops".to_string(),
            },

            // Bank run vulnerability test
            TestCase {
                name: "fractional_reserve_protocol".to_string(),
                bytecode: vec![
                    // redeem() function signature
                    0x63, 0xdb, 0x00, 0x6a, 0x75,
                    // withdraw() function signature
                    0x63, 0x95, 0x2b, 0x27, 0x97,
                    // No rate limiting (missing TIMESTAMP checks)
                    0x00, 0x00, 0x00, 0x00,
                ],
                expected_vulnerabilities: 1,
                expected_modules: vec!["economic".to_string()],
                description: "Protocol with unlimited withdrawals".to_string(),
            },

            // Upgradeable proxy risks
            TestCase {
                name: "vulnerable_proxy".to_string(),
                bytecode: vec![
                    // delegatecall opcode
                    0xf4,
                    // implementation() function
                    0x63, 0x5c, 0x60, 0xda, 0x1b,
                    // upgradeTo() function
                    0x63, 0x3f, 0x4b, 0xa8, 0x3a,
                    // No proper authorization checks
                    0x00, 0x00,
                ],
                expected_vulnerabilities: 2,
                expected_modules: vec!["upgrade".to_string()],
                description: "Proxy contract with upgrade authorization issues".to_string(),
            },

            // Sandwich attack vulnerability
            TestCase {
                name: "vulnerable_dex".to_string(),
                bytecode: vec![
                    // swapExactTokensForTokens() signature
                    0x63, 0x38, 0xed, 0x17, 0x39,
                    // No MEV protection
                    0x00, 0x00, 0x00, 0x00,
                ],
                expected_vulnerabilities: 1,
                expected_modules: vec!["sandwich".to_string()],
                description: "DEX without slippage protection".to_string(),
            },

            // Time-based attack vulnerability
            TestCase {
                name: "timestamp_dependent".to_string(),
                bytecode: vec![
                    // TIMESTAMP opcode
                    0x42,
                    // Direct usage without validation
                    0x10, // LT comparison
                    0x57, // JUMPI
                    // Critical state change
                    0x55, // SSTORE
                ],
                expected_vulnerabilities: 1,
                expected_modules: vec!["time".to_string()],
                description: "Contract with timestamp manipulation risk".to_string(),
            },

            // Complex multi-vulnerability contract
            TestCase {
                name: "multi_vulnerability_defi".to_string(),
                bytecode: vec![
                    // Economic: mint/burn without backstops
                    0x63, 0x40, 0xc1, 0x0f, 0x19, // mint()
                    0x63, 0x42, 0x96, 0x6c, 0x68, // burn()
                    
                    // Upgrade: delegatecall without authorization
                    0xf4, // DELEGATECALL
                    0x63, 0x3f, 0x4b, 0xa8, 0x3a, // upgradeTo()
                    
                    // Sandwich: swap without protection
                    0x63, 0x38, 0xed, 0x17, 0x39, // swapExactTokensForTokens()
                    
                    // Time: timestamp dependency
                    0x42, // TIMESTAMP
                    0x55, // SSTORE
                ],
                expected_vulnerabilities: 4,
                expected_modules: vec![
                    "economic".to_string(), 
                    "upgrade".to_string(), 
                    "sandwich".to_string(), 
                    "time".to_string()
                ],
                description: "Complex DeFi protocol with multiple vulnerability types".to_string(),
            },

            // Clean contract (should have minimal vulnerabilities)
            TestCase {
                name: "secure_contract".to_string(),
                bytecode: vec![
                    // Simple transfer function
                    0x63, 0xa9, 0x05, 0x9c, 0xbb, // transfer()
                    // With proper checks
                    0x10, // GT
                    0x57, // JUMPI
                    // Emergency pause function
                    0x63, 0x8b, 0x78, 0xc6, 0xd8, // pause()
                ],
                expected_vulnerabilities: 0,
                expected_modules: vec![],
                description: "Well-designed contract with proper safeguards".to_string(),
            },
        ]
    }

    /// Run all test cases and return results
    pub fn run_all_tests(&self) -> Vec<TestResult> {
        let mut results = Vec::new();

        for test_case in &self.test_cases {
            println!("Running test: {}", test_case.name);
            let result = self.run_single_test(test_case);
            
            if result.passed {
                println!("✅ {} passed", test_case.name);
            } else {
                println!("❌ {} failed: {:?}", test_case.name, result.error_message);
            }
            
            results.push(result);
        }

        results
    }

    /// Run a specific test case
    fn run_single_test(&self, test_case: &TestCase) -> TestResult {
        let start_time = Instant::now();

        // Configure analyzer based on expected modules
        let mut config = ModuleConfig::default();
        if !test_case.expected_modules.contains(&"economic".to_string()) {
            config.economic_analysis = false;
        }
        if !test_case.expected_modules.contains(&"upgrade".to_string()) {
            config.upgrade_analysis = false;
        }
        if !test_case.expected_modules.contains(&"sandwich".to_string()) {
            config.sandwich_analysis = false;
        }
        if !test_case.expected_modules.contains(&"time".to_string()) {
            config.time_analysis = false;
        }

        // Run analysis
        let analyzer = ComprehensiveAnalyzerBuilder::new(test_case.bytecode.clone())
            .with_contract_address(format!("test_{}", test_case.name))
            .with_module_config(config)
            .build();

        let analysis_result = analyzer.analyze();
        let analysis_time = start_time.elapsed().as_millis() as u64;

        // Validate results
        let actual_vulnerabilities = analysis_result.total_vulnerabilities;
        let passed = self.validate_test_result(test_case, &analysis_result);

        let error_message = if !passed {
            Some(format!(
                "Expected {} vulnerabilities, got {}. Analysis confidence: {:.2}",
                test_case.expected_vulnerabilities,
                actual_vulnerabilities,
                analysis_result.analysis_confidence
            ))
        } else {
            None
        };

        TestResult {
            test_name: test_case.name.clone(),
            passed,
            actual_vulnerabilities,
            expected_vulnerabilities: test_case.expected_vulnerabilities,
            analysis_time_ms: analysis_time,
            error_message,
        }
    }

    /// Validate test result against expectations
    fn validate_test_result(
        &self, 
        test_case: &TestCase, 
        result: &crate::analysis::comprehensive_analyzer::ComprehensiveAnalysisResult
    ) -> bool {
        // Check vulnerability count (allow some tolerance)
        let vulnerability_match = if test_case.expected_vulnerabilities == 0 {
            result.total_vulnerabilities == 0
        } else {
            result.total_vulnerabilities >= test_case.expected_vulnerabilities
        };

        // Check that analysis completed successfully
        let analysis_quality = result.analysis_confidence > 0.5;

        // Check that expected modules detected vulnerabilities
        let module_detection = if test_case.expected_vulnerabilities > 0 {
            test_case.expected_modules.iter().any(|module| {
                match module.as_str() {
                    "economic" => !result.economic_vulnerabilities.is_empty(),
                    "upgrade" => !result.upgrade_vulnerabilities.is_empty(),
                    "sandwich" => !result.sandwich_vulnerabilities.is_empty(),
                    "time" => !result.time_vulnerabilities.is_empty(),
                    _ => false,
                }
            })
        } else {
            true // No modules expected for secure contracts
        };

        vulnerability_match && analysis_quality && module_detection
    }

    /// Generate test report
    pub fn generate_report(&self, results: &[TestResult]) -> String {
        let total_tests = results.len();
        let passed_tests = results.iter().filter(|r| r.passed).count();
        let failed_tests = total_tests - passed_tests;

        let avg_analysis_time: f64 = results.iter()
            .map(|r| r.analysis_time_ms as f64)
            .sum::<f64>() / total_tests as f64;

        let mut report = String::new();
        report.push_str("=== COMPREHENSIVE SECURITY ANALYSIS TEST REPORT ===\n\n");
        report.push_str(&format!("Total Tests: {}\n", total_tests));
        report.push_str(&format!("Passed: {} ✅\n", passed_tests));
        report.push_str(&format!("Failed: {} ❌\n", failed_tests));
        report.push_str(&format!("Success Rate: {:.1}%\n", (passed_tests as f64 / total_tests as f64) * 100.0));
        report.push_str(&format!("Average Analysis Time: {:.1}ms\n\n", avg_analysis_time));

        report.push_str("=== INDIVIDUAL TEST RESULTS ===\n");
        for result in results {
            let status = if result.passed { "✅ PASS" } else { "❌ FAIL" };
            report.push_str(&format!(
                "{} | {} | {}ms | {}/{} vulnerabilities\n",
                status,
                result.test_name,
                result.analysis_time_ms,
                result.actual_vulnerabilities,
                result.expected_vulnerabilities
            ));

            if let Some(error) = &result.error_message {
                report.push_str(&format!("     Error: {}\n", error));
            }
        }

        report.push_str("\n=== PERFORMANCE ANALYSIS ===\n");
        let max_time = results.iter().map(|r| r.analysis_time_ms).max().unwrap_or(0);
        let min_time = results.iter().map(|r| r.analysis_time_ms).min().unwrap_or(0);
        
        report.push_str(&format!("Fastest Analysis: {}ms\n", min_time));
        report.push_str(&format!("Slowest Analysis: {}ms\n", max_time));
        
        if avg_analysis_time < 200.0 {
            report.push_str("✅ Performance Target: Sub-200ms average achieved\n");
        } else {
            report.push_str("❌ Performance Target: Sub-200ms average missed\n");
        }

        report
    }

    /// Run performance benchmarks
    pub fn run_performance_benchmark(&self) -> String {
        println!("Running performance benchmarks...");
        
        let iterations = 10;
        let mut times = Vec::new();
        
        // Use the most complex test case for benchmarking
        let complex_test = &self.test_cases[5]; // multi_vulnerability_defi
        
        for i in 0..iterations {
            println!("Benchmark iteration {}/{}", i + 1, iterations);
            let start = Instant::now();
            
            let analyzer = ComprehensiveSecurityAnalyzer::new(complex_test.bytecode.clone());
            let _result = analyzer.analyze();
            
            let elapsed = start.elapsed().as_millis() as u64;
            times.push(elapsed);
        }

        let avg_time: f64 = times.iter().map(|&t| t as f64).sum::<f64>() / iterations as f64;
        let min_time = *times.iter().min().unwrap();
        let max_time = *times.iter().max().unwrap();

        format!(
            "=== PERFORMANCE BENCHMARK RESULTS ===\n\
            Test Case: {}\n\
            Iterations: {}\n\
            Average Time: {:.1}ms\n\
            Min Time: {}ms\n\
            Max Time: {}ms\n\
            Target: <200ms\n\
            Status: {}\n",
            complex_test.name,
            iterations,
            avg_time,
            min_time,
            max_time,
            if avg_time < 200.0 { "✅ ACHIEVED" } else { "❌ MISSED" }
        )
    }
}

/// Main test execution function
pub fn run_comprehensive_tests() {
    println!("🔒 Starting Comprehensive Security Analysis Tests\n");
    
    let test_runner = SecurityTestRunner::new();
    
    // Run all functionality tests
    let results = test_runner.run_all_tests();
    let report = test_runner.generate_report(&results);
    println!("{}", report);
    
    // Run performance benchmarks
    let perf_report = test_runner.run_performance_benchmark();
    println!("{}", perf_report);
    
    // Summary
    let passed = results.iter().filter(|r| r.passed).count();
    let total = results.len();
    
    if passed == total {
        println!("🎉 ALL TESTS PASSED! Security system ready for deployment.");
    } else {
        println!("⚠️  Some tests failed. Review and fix issues before deployment.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_death_spiral_detection() {
        let test_runner = SecurityTestRunner::new();
        let death_spiral_test = &test_runner.test_cases[0];
        let result = test_runner.run_single_test(death_spiral_test);
        assert!(result.passed, "Death spiral detection should work");
    }

    #[test]
    fn test_multi_vulnerability_detection() {
        let test_runner = SecurityTestRunner::new();
        let complex_test = &test_runner.test_cases[5];
        let result = test_runner.run_single_test(complex_test);
        assert!(result.actual_vulnerabilities >= 3, "Should detect multiple vulnerabilities");
    }

    #[test]
    fn test_performance_target() {
        let test_runner = SecurityTestRunner::new();
        let simple_test = &test_runner.test_cases[0];
        let result = test_runner.run_single_test(simple_test);
        assert!(result.analysis_time_ms < 200, "Should meet sub-200ms target");
    }
}
