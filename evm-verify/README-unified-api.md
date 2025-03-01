# EVM Verify Unified API

The EVM Verify Unified API provides a comprehensive interface for analyzing Ethereum smart contracts using both Proof-Carrying Code (PCC) and Proof-Carrying Data (PCD) approaches.

## Overview

The Unified API integrates two powerful verification approaches:

1. **Proof-Carrying Code (PCC)**: Focuses on static analysis of bytecode to detect vulnerabilities and security issues.
2. **Proof-Carrying Data (PCD)**: Focuses on dynamic state transitions and data flow to identify vulnerabilities.

By combining these approaches, the Unified API provides more comprehensive security analysis than either approach alone.

## Features

- Unified interface for both PCC and PCD analysis
- Configurable to use either or both approaches
- Comprehensive vulnerability detection
- Zero-knowledge proof generation and verification (coming soon)
- Easy integration with existing Ethereum tools

## Usage

```rust
use evm_verify::UnifiedVerifier;
use ethers::types::Bytes;

// Create a unified verifier
let verifier = UnifiedVerifier::new();

// Analyze bytecode
let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]); // PUSH1 1 PUSH1 0 SSTORE
let report = verifier.analyze_bytecode(bytecode).unwrap();

// Check for vulnerabilities
if !report.vulnerabilities.is_empty() {
    println!("Found {} vulnerabilities!", report.vulnerabilities.len());
    
    for vuln in &report.vulnerabilities {
        println!("{}: {}", vuln.title, vuln.description);
        println!("Severity: {:?}", vuln.severity);
        println!("Recommendation: {}", vuln.recommendation);
    }
}
```

## Configuration

You can configure the verifier to use only PCC, only PCD, or both:

```rust
// Use only PCC
let pcc_verifier = UnifiedVerifier::with_config(false, true);

// Use only PCD
let pcd_verifier = UnifiedVerifier::with_config(true, false);

// Use both (default)
let combined_verifier = UnifiedVerifier::with_config(true, true);
```

## Security Checks

The Unified API can detect a wide range of vulnerabilities, including:

- Reentrancy vulnerabilities
- Access control issues
- Unchecked external calls
- Gas limit problems
- Integer overflow/underflow
- Flash loan vulnerabilities
- Timestamp dependencies
- Signature replay vulnerabilities
- Proxy contract vulnerabilities
- Oracle manipulation
- MEV vulnerabilities
- Governance vulnerabilities

## Future Enhancements

- Enhanced zero-knowledge proof generation and verification
- Integration with formal verification tools
- Support for more complex vulnerability patterns
- Performance optimizations for large contracts
- Integration with blockchain explorers and development tools

## Examples

See the `examples` directory for complete usage examples, including:

- `unified_api_example.rs`: Basic usage of the Unified API
- More examples coming soon

## License

This project is licensed under the MIT License - see the LICENSE file for details.
