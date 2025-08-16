//! Tests for cross-protocol arbitrage manipulation detection

use crate::analysis::cross_protocol_arbitrage::{
    CrossProtocolArbitrageAnalyzer, DEXProtocol, DEXType, SwapEvent, ArbitrageManipulationKind
};
use ethers::types::{H160, H256, U256};

#[test]
fn test_analyzer_creation() {
    let analyzer = CrossProtocolArbitrageAnalyzer::new();
    
    // Basic test that analyzer can be created
    let manipulations = analyzer.detect_arbitrage_manipulations();
    assert!(manipulations.is_empty(), "New analyzer should have no manipulations");
}

#[test]
fn test_price_discrepancy_calculation() {
    let analyzer = CrossProtocolArbitrageAnalyzer::new();
    
    // Create swaps with different effective prices and protocols
    let mut swap1 = create_swap_with_price(1000, 950); // Lower effective price
    swap1.protocol.name = "Protocol A".to_string();
    
    let mut swap2 = create_swap_with_price(950, 1050); // Higher effective price - arbitrage
    swap2.protocol.name = "Protocol B".to_string();
    
    let swaps = vec![&swap1, &swap2];
    let price_analysis = analyzer.calculate_price_discrepancies(&swaps);
    
    assert!(price_analysis.maximum_deviation > 0.0, "Should detect price discrepancy");
    assert!(price_analysis.maximum_deviation > 0.05, "Should exceed manipulation threshold");
}

#[test]
fn test_arbitrage_profit_calculation() {
    let analyzer = CrossProtocolArbitrageAnalyzer::new();
    
    let steps = vec![
        create_arbitrage_step(U256::from(1000), U256::from(950)),
        create_arbitrage_step(U256::from(950), U256::from(1050)),
    ];
    
    let profit = analyzer.calculate_arbitrage_profit(&steps);
    assert!(profit > U256::zero(), "Should calculate positive profit");
}

fn create_uniswap_swap() -> SwapEvent {
    SwapEvent {
        block_number: 100,
        protocol: DEXProtocol {
            name: "Uniswap V2".to_string(),
            router_contract: H160::from([1u8; 20]),
            factory_contract: H160::from([2u8; 20]),
            protocol_type: DEXType::UniswapV2,
        },
        token_in: H160::from([10u8; 20]),
        token_out: H160::from([11u8; 20]),
        amount_in: U256::from(1000),
        amount_out: U256::from(950),
        trader: H160::from([20u8; 20]),
        transaction_hash: H256::from([30u8; 32]),
    }
}

fn create_sushiswap_swap() -> SwapEvent {
    SwapEvent {
        block_number: 100,
        protocol: DEXProtocol {
            name: "SushiSwap".to_string(),
            router_contract: H160::from([3u8; 20]),
            factory_contract: H160::from([4u8; 20]),
            protocol_type: DEXType::SushiSwap,
        },
        token_in: H160::from([11u8; 20]),
        token_out: H160::from([10u8; 20]),
        amount_in: U256::from(950),
        amount_out: U256::from(1050),
        trader: H160::from([20u8; 20]),
        transaction_hash: H256::from([31u8; 32]),
    }
}

fn create_swap_with_price(amount_in: u64, amount_out: u64) -> SwapEvent {
    SwapEvent {
        block_number: 100,
        protocol: DEXProtocol {
            name: "Test DEX".to_string(),
            router_contract: H160::from([1u8; 20]),
            factory_contract: H160::from([2u8; 20]),
            protocol_type: DEXType::UniswapV2,
        },
        token_in: H160::from([10u8; 20]),
        token_out: H160::from([11u8; 20]),
        amount_in: U256::from(amount_in),
        amount_out: U256::from(amount_out),
        trader: H160::from([20u8; 20]),
        transaction_hash: H256::from([30u8; 32]),
    }
}

fn create_arbitrage_step(amount_in: U256, amount_out: U256) -> crate::analysis::cross_protocol_arbitrage::ArbitrageStep {
    use crate::analysis::cross_protocol_arbitrage::ArbitrageStep;
    
    ArbitrageStep {
        protocol: DEXProtocol {
            name: "Test DEX".to_string(),
            router_contract: H160::from([1u8; 20]),
            factory_contract: H160::from([2u8; 20]),
            protocol_type: DEXType::UniswapV2,
        },
        token_in: H160::from([10u8; 20]),
        token_out: H160::from([11u8; 20]),
        amount_in,
        expected_amount_out: amount_out,
        actual_amount_out: amount_out,
        price_impact: 0.01,
    }
}
