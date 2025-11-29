use ethers::{
    providers::{Http, Provider, Middleware},
    types::{BlockNumber, U64},
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔗 Testing multiple RPC endpoints...");
    
    // Try multiple public RPC endpoints
    let rpc_endpoints = vec![
        "http://localhost:8545",
        "https://ethereum-rpc.publicnode.com",
        "https://rpc.ankr.com/eth",
        "http://localhost:8545",
        "https://cloudflare-eth.com",
    ];
    
    for (i, rpc_url) in rpc_endpoints.iter().enumerate() {
        println!("\n{}️⃣ Testing endpoint: {}", i + 1, rpc_url);
        
        // Create provider
        let provider = match Provider::<Http>::try_from(*rpc_url) {
            Ok(p) => Arc::new(p),
            Err(e) => {
                println!("  ❌ Failed to create provider: {}", e);
                continue;
            }
        };
        
        // Test: Get latest block number
        match provider.get_block_number().await {
            Ok(block_number) => {
                println!("  ✅ Latest block: {} - ENDPOINT WORKS!", block_number);
                
                // Test a specific recent block
                let test_block = block_number.as_u64() - 1;
                match provider.get_block_with_txs(BlockNumber::Number(U64::from(test_block))).await {
                    Ok(Some(block)) => {
                        println!("  ✅ Block {} - {} transactions", test_block, block.transactions.len());
                        println!("  🎉 WORKING ENDPOINT FOUND: {}", rpc_url);
                        
                        // This endpoint works, let's test our target blocks
                        return test_target_blocks(provider).await;
                    },
                    Ok(None) => {
                        println!("  ⚠️  Block {} returned None", test_block);
                    },
                    Err(e) => {
                        println!("  ❌ Block {} error: {}", test_block, e);
                    }
                }
            },
            Err(e) => {
                println!("  ❌ Failed to get latest block: {}", e);
                continue;
            }
        }
    }
    
    println!("\n❌ No working RPC endpoints found!");
    Ok(())
}

async fn test_target_blocks(provider: Arc<Provider<Http>>) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🎯 Testing target blocks from previous zkEVM tests...");
    
    let test_blocks = vec![
        22_959_215_u64, // From previous testing: 172 transactions, 16M gas
        22_961_551_u64, // From previous testing: 239 transactions total  
        18_500_000_u64, // From previous testing: 935 transactions across 5 blocks
        15_000_000_u64, // Historical that found vulnerabilities
    ];
    
    for block_num in test_blocks {
        println!("🔍 Testing block {}...", block_num);
        match provider.get_block_with_txs(BlockNumber::Number(U64::from(block_num))).await {
            Ok(Some(block)) => {
                println!("  ✅ Block {} found - {} transactions", block_num, block.transactions.len());
                if block.transactions.len() > 0 {
                    println!("    📋 First transaction: {:?}", block.transactions[0].hash);
                }
            },
            Ok(None) => {
                println!("  ⚠️  Block {} exists but returned None", block_num);
            },
            Err(e) => {
                println!("  ❌ Block {} error: {}", block_num, e);
            }
        }
    }
    
    println!("\n🏁 RPC endpoint test complete!");
    Ok(())
}
