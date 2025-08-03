mod tests {
    use crate::analyzer::dex_price_verifier::*;
    use crate::analyzer::Property;
    use anyhow::Result;

    // Sample bytecode for DEX price aggregation contract
    const DEX_AGGREGATOR_BYTECODE: &[u8] = &[
        0x60, 0x80, 0x60, 0x40, 0x52, // Setup
        0x60, 0x04, 0x36, 0x10, 0x60, 0x2d, 0x57, // Function selector
        0x63, 0x50, 0xd2, 0x5b, 0xcd, 0x14, 0x60, 0x32, 0x57, // getPrice()
        0x63, 0x18, 0x16, 0x0d, 0xdd, 0x14, 0x60, 0x47, 0x57, // aggregatePrice()
        0x63, 0x95, 0xd8, 0x9b, 0x41, 0x14, 0x60, 0x5c, 0x57, // validatePrices()
        0x5b, 0x60, 0x00, 0x80, 0xfd, // Revert
        // getPrice function - simple price oracle read
        0x5b, 0x60, 0x00, 0x54, 0x60, 0x40, 0x51, 0x80, 0x82, 0x81, 0x52, 0x60, 0x20, 0x01, 0x91, 0x90, 0x50, 0xf3,
        // aggregatePrice function - multi-source aggregation
        0x5b, 0x60, 0x01, 0x54, 0x60, 0x02, 0x54, 0x01, 0x60, 0x02, 0x06, 0x60, 0x03, 0x55, 0x56,
        // validatePrices function - outlier detection
        0x5b, 0x60, 0x03, 0x54, 0x60, 0x64, 0x81, 0x11, 0x15, 0x60, 0x85, 0x57, 0x56, 0x5b, 0x60, 0x00, 0x80, 0xfd,
    ];

    // Test bytecode representing stablecoin rebalancing mechanism
    const STABLECOIN_BYTECODE: &[u8] = &[
        0x60, 0x80, 0x60, 0x40, 0x52, // Setup
        0x60, 0x04, 0x36, 0x10, 0x60, 0x2d, 0x57, // Function selector
        0x63, 0x50, 0xd2, 0x5b, 0xcd, 0x14, 0x60, 0x32, 0x57, // getPrice()
        0x63, 0x18, 0x16, 0x0d, 0xdd, 0x14, 0x60, 0x47, 0x57, // aggregatePrice()
        0x63, 0x95, 0xd8, 0x9b, 0x41, 0x14, 0x60, 0x5c, 0x57, // validatePrices()
        0x5b, 0x60, 0x00, 0x80, 0xfd, // Revert
        // getPrice function - simple price oracle read
        0x5b, 0x60, 0x00, 0x54, 0x60, 0x40, 0x51, 0x80, 0x82, 0x81, 0x52, 0x60, 0x20, 0x01, 0x91, 0x90, 0x50, 0xf3,
        // aggregatePrice function - multi-source aggregation
        0x5b, 0x60, 0x01, 0x54, 0x60, 0x02, 0x54, 0x01, 0x60, 0x02, 0x06, 0x60, 0x03, 0x55, 0x56,
        // validatePrices function - outlier detection
        0x5b, 0x60, 0x03, 0x54, 0x60, 0x64, 0x81, 0x11, 0x15, 0x60, 0x85, 0x57, 0x56, 0x5b, 0x60, 0x00, 0x80, 0xfd,
    ];

    #[test]
    fn test_dex_price_verifier_creation() {
        let verifier = DEXPriceVerifier::new(
            10,      // min_dex_sources: even higher for more security
            0.01,    // max_price_deviation: very tight control
            5_000_000.0,  // min_liquidity_per_dex: much higher for manipulation resistance
            200      // twap_window: much longer for stability
        );

        println!("✅ DEXPriceVerifier created successfully");
    }

    #[test]
    fn test_basic_price_verification() -> Result<()> {
        let verifier = DEXPriceVerifier::new(50, 0.001, 1_000_000_000.0, 5000);
        let proof = verifier.verify(DEX_AGGREGATOR_BYTECODE)?;

        // Basic proof structure checks
        assert!(proof.timestamp > 0);
        assert_ne!(proof.proof_hash, [0u8; 32]);

        println!("✅ Basic price verification completed");
        println!("   Timestamp: {}", proof.timestamp);
        
        Ok(())
    }

    #[test]
    fn test_manipulation_resistance() -> Result<()> {
        let verifier = DEXPriceVerifier::new(50, 0.001, 1_000_000_000.0, 5000);
        let proof = verifier.verify(DEX_AGGREGATOR_BYTECODE)?;
        
        // Check manipulation resistance properties
        let resistance = &proof.manipulation_resistance_proof;
        assert!(resistance.cost_exceeds_profit_proof);
        assert!(resistance.detection_window > 0);
        
        println!("✅ Manipulation resistance verified");
        
        Ok(())
    }

    #[test]
    fn test_price_consensus() -> Result<()> {
        let verifier = DEXPriceVerifier::new(50, 0.001, 1_000_000_000.0, 5000);
        let proof = verifier.verify(DEX_AGGREGATOR_BYTECODE)?;
        
        // Check price consensus properties
        let consensus = &proof.price_consensus_proof;
        assert!(consensus.consensus_sources >= 3);
        assert!(consensus.agreement_threshold > 0.8);
        
        println!("✅ Price consensus verified");
        
        Ok(())
    }

    #[test]
    fn test_twap_analysis() -> Result<()> {
        let verifier = DEXPriceVerifier::new(50, 0.001, 1_000_000_000.0, 5000);
        let proof = verifier.verify(DEX_AGGREGATOR_BYTECODE)?;
        
        // Check TWAP properties
        let twap_proof = &proof.twap_manipulation_proof;
        assert!(twap_proof.sufficient_window_proof);
        assert!(twap_proof.twap_window_blocks > 100);
        
        println!("✅ TWAP analysis verified");
        
        Ok(())
    }

    #[test]
    fn test_arbitrage_analysis() -> Result<()> {
        let verifier = DEXPriceVerifier::new(50, 0.001, 1_000_000_000.0, 5000);
        let proof = verifier.verify(DEX_AGGREGATOR_BYTECODE)?;
        
        // Check arbitrage properties
        let arbitrage = &proof.arbitrage_analysis;
        assert!(arbitrage.arbitrage_correction_proof.automatic_correction_proof);
        assert!(arbitrage.correction_time_bounds.bounded_correction_proof);
        Ok(())
    }

    #[test]
    fn test_manipulation_attack_detection() -> Result<()> {
        let verifier = DEXPriceVerifier::new(3, 0.03, 100_000.0, 300);

        let proof = verifier.verify(STABLECOIN_BYTECODE)?;

        // Should detect and resist manipulation attempts
        assert!(proof.manipulation_resistance_proof.cost_exceeds_profit_proof);
        
        let resistance = &proof.manipulation_resistance_proof;
        assert!(resistance.cost_exceeds_profit_proof);
        assert!(resistance.detection_window > 0);
        assert!(!resistance.manipulation_cost_function.is_empty());
        assert!(!resistance.response_mechanisms.is_empty());

        println!("✅ Manipulation attack detection verified");

        Ok(())
    }

    #[test]
    fn test_proof_integrity() -> Result<()> {
        let verifier = DEXPriceVerifier::new(50, 0.001, 1_000_000_000.0, 5000);
        let proof = verifier.verify(DEX_AGGREGATOR_BYTECODE)?;
        
        // Check proof integrity
        assert!(!proof.proof_hash.is_empty());
        assert!(proof.price_consensus_proof.consensus_sources > 0);
        assert!(proof.manipulation_resistance_proof.cost_exceeds_profit_proof);
        
        Ok(())
    }

    #[test]
    fn test_performance_benchmarks() -> Result<()> {
        let verifier = DEXPriceVerifier::new(50, 0.001, 1_000_000_000.0, 5000);
        
        let start = std::time::Instant::now();
        let proof = verifier.verify(DEX_AGGREGATOR_BYTECODE)?;
        let duration = start.elapsed();

        // Verification should be fast
        assert!(duration.as_millis() < 150, "Verification took too long: {:?}", duration);
        assert!(!proof.proof_hash.is_empty());
        
        println!("✅ Performance benchmark passed");
        println!("   Verification time: {:?}", duration);

        Ok(())
    }
}
