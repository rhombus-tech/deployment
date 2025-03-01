use ethers::types::Bytes;
use std::str::FromStr;
use anyhow::Result;
use evm_verify::api::UnifiedVerifier;

fn main() -> Result<()> {
    // Create a new verifier
    let verifier = UnifiedVerifier::new();
    
    // Sample bytecode (this is a simple ERC20 token contract)
    let bytecode_hex = "608060405234801561001057600080fd5b506040516103bc3803806103bc83398101604081905261002f9161007c565b60405181815233906000907fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef9060200160405180910390a333600090815260208190526040902055610094565b60006020828403121561008e57600080fd5b5051919050565b610319806100a36000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c8063313ce56714610046578063a9059cbb14610064578063dd62ed3e14610077575b600080fd5b61004e6103e8815b60405190815260200160405180910390f35b6100776100723660046101e2565b6100b7565b005b61004e61008536600461020c565b6001600160a01b03918216600090815260016020908152604080832093909416825291909152205490565b3360009081526020819052604090205482111561010f5760405162461bcd60e51b815260206004820152601a60248201527f696e73756666696369656e7420746f6b656e2062616c616e636500000000000060448201526064015b60405180910390fd5b336000908152602081905260408120805483929061012e9084906102b6565b90915550506001600160a01b0383166000908152602081905260408120805483929061015b9084906102cd565b90915550506040518281526001600160a01b0384169033907fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef9060200160405180910390a350505050565b80356001600160a01b03811681146101bd57600080fd5b919050565b634e487b7160e01b600052604160045260246000fd5b600080604083850312156101f557600080fd5b6101fe836101a6565b946020939093013593505050565b6000806040838503121561021f57600080fd5b610228836101a6565b9150610236602084016101a6565b90509250929050565b600181815b8085111561027657816000190482111561025c5761025c6102e5565b8085161561026957918102915b93841c9390800290610240565b509250929050565b6000826102915750600161026f565b816102a05750600061026f565b81600181146102b657600281146102c0576102dc565b600191505061026f565b60ff8411156102d1576102d16102e5565b50506001821b61026f565b5060208310610133831016604e8410600b84101617156102ff575081810a61026f565b61030983836102e5565b806000190482111561031d5761031d6102e5565b029392505050565b600061033460ff841683610282565b9392505050565b600082821015610350576103506102e5565b500390565b634e487b7160e01b600052601160045260246000fdfea2646970667358221220d28cf161457f9f9a136e8bed4cd5b9d5e12abf2f25f3bed8e0be0b34e5e3d76264736f6c63430008100033";
    let bytecode = Bytes::from_str(bytecode_hex)?;
    
    println!("Analyzing bytecode...");
    let report = verifier.analyze_bytecode(bytecode.clone())?;
    
    println!("Analysis report:");
    println!("  - Contract size: {} bytes", report.contract_size);
    println!("  - Vulnerabilities found: {}", report.vulnerabilities.len());
    for (i, vuln) in report.vulnerabilities.iter().enumerate() {
        println!("    {}. {} ({})", i + 1, vuln.title, vuln.severity);
    }
    
    // Generate PCC proof
    println!("\nGenerating PCC proof...");
    match verifier.generate_pcc_proof(&bytecode) {
        Ok(proof) => {
            println!("PCC proof generated successfully!");
            
            // Verify PCC proof
            println!("Verifying PCC proof...");
            match verifier.verify_pcc_proof(&bytecode, &proof) {
                Ok(is_valid) => {
                    println!("PCC proof verification result: {}", if is_valid { "Valid" } else { "Invalid" });
                },
                Err(e) => {
                    println!("Failed to verify PCC proof: {}", e);
                }
            }
        },
        Err(e) => {
            println!("Failed to generate PCC proof: {}", e);
        }
    }
    
    // Generate PCD proof
    println!("\nGenerating PCD proof...");
    match verifier.generate_pcd_proof(&bytecode) {
        Ok(proof) => {
            println!("PCD proof generated successfully!");
            
            // Verify PCD proof
            println!("Verifying PCD proof...");
            match verifier.verify_pcd_proof(&bytecode, &proof) {
                Ok(is_valid) => {
                    println!("PCD proof verification result: {}", if is_valid { "Valid" } else { "Invalid" });
                },
                Err(e) => {
                    println!("Failed to verify PCD proof: {}", e);
                }
            }
        },
        Err(e) => {
            println!("Failed to generate PCD proof: {}", e);
        }
    }
    
    Ok(())
}
