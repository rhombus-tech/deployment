#[cfg(test)]
mod tests {
    use crate::bytecode::analyzer::BytecodeAnalyzer;
    use ethers::types::Bytes;
    use anyhow::Result;
    use std::env;
    use std::fs;
    use std::path::Path;
    use hex;

    // Helper function to load bytecode from a file
    fn load_bytecode_from_file(path: &str) -> Result<Bytes> {
        let bytecode_hex = fs::read_to_string(path)?;
        let bytecode_bytes = hex::decode(bytecode_hex.trim())?;
        Ok(Bytes::from(bytecode_bytes))
    }

    // Helper function to analyze a contract
    fn analyze_contract(bytecode: Bytes) -> Result<()> {
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        
        // We want to see all analysis results
        analyzer.set_test_mode(false);
        
        let analysis = analyzer.analyze()?;
        
        // Print analysis results
        println!("Contract Analysis Results:");
        println!("- Code Length: {} bytes", analysis.runtime.code_length);
        println!("- Memory Accesses: {}", analysis.memory_accesses.len());
        println!("- Storage Accesses: {}", analysis.runtime.storage_accesses.len());
        println!("- Warnings: {}", analysis.warnings.len());
        println!("- Delegate Calls: {}", analysis.delegate_calls.len());
        
        // Print warnings if any
        if !analysis.warnings.is_empty() {
            println!("\nWarnings:");
            for warning in &analysis.warnings {
                println!("  - {}", warning);
            }
        }
        
        // Print delegate calls if any
        if !analysis.delegate_calls.is_empty() {
            println!("\nDelegate Calls:");
            for call in &analysis.delegate_calls {
                println!("  - At PC {}: {}", call.pc, call.target);
            }
        }
        
        // Basic assertions
        assert!(analysis.runtime.code_length > 0);
        
        Ok(())
    }

    #[test]
    fn test_usdt_contract() -> Result<()> {
        // Path to USDT bytecode file
        let bytecode_path = "test_data/0xdAC17F958D2ee523a2206206994597C13D831ec7_bytecode.hex";
        
        // Skip test if file doesn't exist
        if !Path::new(bytecode_path).exists() {
            println!("Skipping USDT contract test: bytecode file not found at {}", bytecode_path);
            println!("Run the fetch_bytecode tool to download the contract bytecode:");
            println!("ETHERSCAN_API_KEY=your_key_here cargo run --bin fetch_bytecode 0xdAC17F958D2ee523a2206206994597C13D831ec7");
            return Ok(());
        }
        
        println!("Analyzing USDT contract (Tether)...");
        let bytecode = load_bytecode_from_file(bytecode_path)?;
        analyze_contract(bytecode)?;
        
        Ok(())
    }

    #[test]
    fn test_uniswap_v2_router_contract() -> Result<()> {
        // Path to Uniswap V2 Router bytecode file
        let bytecode_path = "test_data/0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D_bytecode.hex";
        
        // Skip test if file doesn't exist
        if !Path::new(bytecode_path).exists() {
            println!("Skipping Uniswap V2 Router contract test: bytecode file not found at {}", bytecode_path);
            println!("Run the fetch_bytecode tool to download the contract bytecode:");
            println!("ETHERSCAN_API_KEY=your_key_here cargo run --bin fetch_bytecode 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D");
            return Ok(());
        }
        
        println!("Analyzing Uniswap V2 Router contract...");
        let bytecode = load_bytecode_from_file(bytecode_path)?;
        analyze_contract(bytecode)?;
        
        Ok(())
    }
}

#[cfg(test)]
mod live_contracts_tests {
    use crate::bytecode::analyzer::BytecodeAnalyzer;
    use ethers::{
        providers::{Http, Provider, Middleware},
        types::{Address, Bytes, H160},
    };
    use anyhow::Result;
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    // Helper function to analyze a contract
    fn analyze_contract(bytecode: Bytes) -> Result<()> {
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        
        // We want to see all analysis results
        analyzer.set_test_mode(false);
        
        let analysis = analyzer.analyze()?;
        
        // Print analysis results
        println!("Contract Analysis Results:");
        println!("- Code Length: {} bytes", analysis.runtime.code_length);
        println!("- Memory Accesses: {}", analysis.memory_accesses.len());
        println!("- Storage Accesses: {}", analysis.runtime.storage_accesses.len());
        println!("- Warnings: {}", analysis.warnings.len());
        println!("- Delegate Calls: {}", analysis.delegate_calls.len());
        
        // Print warnings if any
        if !analysis.warnings.is_empty() {
            println!("\nWarnings:");
            for warning in &analysis.warnings {
                println!("  - {}", warning);
            }
        }
        
        // Print delegate calls if any
        if !analysis.delegate_calls.is_empty() {
            println!("\nDelegate Calls:");
            for call in &analysis.delegate_calls {
                println!("  - At PC {}: {}", call.pc, call.target);
            }
        }
        
        // Basic assertions
        assert!(analysis.runtime.code_length > 0);
        
        Ok(())
    }

    #[test]
    fn test_fetch_and_analyze_usdt() -> Result<()> {
        // Create a runtime for async code
        let rt = Runtime::new()?;
        
        // Run the async code in the runtime
        rt.block_on(async {
            // Connect to Ethereum mainnet
            let provider = Provider::<Http>::try_from(
                "https://mainnet.infura.io/v3/YOUR_INFURA_KEY"
            )?;
            let provider = Arc::new(provider);
            
            // USDT contract address
            let address = Address::from_str("0xdAC17F958D2ee523a2206206994597C13D831ec7")?;
            
            println!("Fetching USDT contract bytecode...");
            let bytecode = provider.get_code(address, None).await?;
            
            if bytecode.0.is_empty() {
                println!("Failed to fetch bytecode: empty response");
                return Ok(());
            }
            
            println!("Analyzing USDT contract...");
            analyze_contract(bytecode)?;
            
            Ok::<(), anyhow::Error>(())
        })?;
        
        Ok(())
    }
}
