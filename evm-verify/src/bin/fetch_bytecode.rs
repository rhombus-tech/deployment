use std::env;
use std::fs::File;
use std::io::Write;
use reqwest::blocking::Client;
use serde_json::Value;
use hex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get contract address from command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: fetch_bytecode <contract_address>");
        println!("Example: fetch_bytecode 0xdAC17F958D2ee523a2206206994597C13D831ec7");
        println!("\nNote: Set the ETHERSCAN_API_KEY environment variable before running.");
        println!("Example: export ETHERSCAN_API_KEY=your_api_key_here");
        return Ok(());
    }
    
    // Get API key from environment variable
    let api_key = match env::var("ETHERSCAN_API_KEY") {
        Ok(key) => key,
        Err(_) => {
            println!("Error: ETHERSCAN_API_KEY environment variable not set");
            println!("Please set it using: export ETHERSCAN_API_KEY=your_api_key_here");
            return Ok(());
        }
    };
    
    let contract_address = &args[1];
    println!("Fetching bytecode for contract: {}", contract_address);
    
    // Create the API URL
    let url = format!(
        "https://api.etherscan.io/api?module=proxy&action=eth_getCode&address={}&tag=latest&apikey={}",
        contract_address, api_key
    );
    
    // Make the request
    let client = Client::new();
    let response = client.get(&url).send()?;
    let json: Value = response.json()?;
    
    // Extract the bytecode
    if let Some(result) = json.get("result").and_then(|r| r.as_str()) {
        println!("Bytecode retrieved successfully!");
        println!("Bytecode length: {} characters", result.len());
        
        // Remove the '0x' prefix if present
        let bytecode = if result.starts_with("0x") {
            &result[2..]
        } else {
            result
        };
        
        // Save to file
        let filename = format!("{}_bytecode.hex", contract_address);
        let mut file = File::create(&filename)?;
        file.write_all(bytecode.as_bytes())?;
        println!("Bytecode saved to {}", filename);
        
        // Also save as binary
        let bin_filename = format!("{}_bytecode.bin", contract_address);
        let bytes = hex::decode(bytecode)?;
        let mut bin_file = File::create(&bin_filename)?;
        bin_file.write_all(&bytes)?;
        println!("Binary bytecode saved to {}", bin_filename);
        
    } else if let Some(error) = json.get("error") {
        println!("Error fetching bytecode: {:?}", error);
    } else {
        println!("Unexpected response format: {:?}", json);
    }
    
    Ok(())
}
