# EVM Verify

A formal verification tool for Ethereum smart contracts that provides mathematical guarantees about contract safety and behavior.

---

# 🎓 Simple Explanation: What is EVM Verify?

Imagine you're building a house out of LEGO bricks:

👀 **Regular Security Tools**
- Like having a friend look at your house
- They check if it looks stable
- They might miss problems on the other side
- They can only find issues they've seen before

🔍 **EVM Verify**
- Like having a special LEGO scanner
- It checks EVERY brick and connection
- It PROVES your house can't fall down
- It shows you exactly why it's safe

For example:
- Regular Tool: "I looked around and didn't see any problems"
- EVM Verify: "I can prove this house will stand even in an earthquake"

When you deploy a smart contract, you want to be 100% sure it's safe. That's what we do - we don't just look for problems, we mathematically prove your contract is secure.

---

## Overview

EVM Verify is a comprehensive tool for formally verifying Ethereum smart contracts. It uses a combination of static analysis, symbolic execution, and cryptographic proof systems to provide mathematical guarantees about contract safety and behavior.

Key features include:

- **Bytecode Analysis**: Detects common vulnerabilities in EVM bytecode
- **Proof-Carrying Code (PCC)**: Verifies that a contract satisfies certain safety properties
- **Proof-Carrying Data (PCD)**: Ensures that contract state transitions are valid
- **Accumulation-Based Verification**: Efficiently verify multiple proofs using an accumulation scheme

## Accumulation-Based PCD Implementation

The latest version of EVM Verify includes a new accumulation-based Proof-Carrying Data (PCD) implementation. This implementation provides several advantages over the traditional PCD approach:

- **Efficient Proof Aggregation**: Combine multiple proofs into a single proof that can be verified more efficiently
- **Reduced Verification Overhead**: Verify multiple proofs in a single operation
- **Incremental Verification**: Add new proofs to an existing accumulator without re-verifying all previous proofs
- **Enhanced Security**: Maintain the same security guarantees as the traditional PCD approach

### Technical Details

The accumulation-based PCD implementation uses the following components:

- **Accumulation Scheme**: Based on the arkworks accumulation library
- **Cryptographic Primitives**: Uses the Bn254 elliptic curve for compatibility with Ethereum
- **Proof System**: Uses the Groth16 zk-SNARK proof system
- **Sponge Construction**: Uses PoseidonSponge for cryptographic operations

### Usage

To use the accumulation-based PCD implementation, enable the `accumulation` feature flag:

```bash
# Build with accumulation feature
cargo build --features accumulation

# Run with accumulation feature
cargo run --features accumulation
```

In your code, you can use the `PCDAdapter` with the accumulation feature:

```rust
// Create a new PCDAdapter with accumulation
let pcd_adapter = PCDAdapter::new();

// Verify bytecode
let verification_result = pcd_adapter.verify_bytecode(bytecode)?;

// Generate proof
let (proof, public_inputs, vk) = pcd_adapter.generate_proof(bytecode)?;

// Accumulate proofs
let accumulated_proof = pcd_adapter.accumulate_proofs(&[proof1, proof2])?;

// Verify accumulated proof
let is_valid = pcd_adapter.verify_accumulated_proof(&accumulated_proof)?;
```

## How We're Different

🔍 **Traditional Security Tools**
- Look for known vulnerabilities
- Can miss unknown issues
- Take days or weeks
- Results may vary

✅ **EVM Verify**
- Proves security properties
- Catches ALL violations
- Results in minutes
- Always consistent

### Why Choose EVM Verify?

1. **Deployment Confidence**
   - Traditional tools say: "No issues found in our scan"
   - EVM Verify proves: "This contract cannot be reentered"

2. **Gas Savings**
   - Traditional tools say: "Consider removing SafeMath"
   - EVM Verify proves: "This operation cannot overflow, SafeMath unnecessary"

3. **Memory Safety**
   - Traditional tools say: "Possible out-of-bounds access"
   - EVM Verify proves: "All memory accesses are within bounds"

4. **State Management**
   - Traditional tools say: "Complex state modifications detected"
   - EVM Verify proves: "State transitions preserve invariants"

### Current Features

**Security Analysis**
- Reentrancy detection and prevention
- Delegatecall safety verification
- State transition validation
- Access control pattern analysis
- Complex operation sequence validation

**Memory & Storage**
- Memory bounds checking
- Memory read-before-write detection
- Storage access pattern analysis
- Memory safety guarantees
- Stack manipulation verification

**Bitwise & Math Operations**
- Bitmask operation safety
- Bitwise operation validation
- Unsafe shift detection
- Integer overflow/underflow prevention

**Contract Structure**
- Constructor argument validation
- Runtime code analysis
- Cross-function interaction checks
- Real-world contract testing

### Future Capabilities
Through Proof-Carrying Code (PCC) and Proof-Carrying Data (PCD), we will soon provide:

1. **Provable Safety Properties**
   - Mathematical proofs that vulnerabilities CANNOT exist
   - Stronger than traditional vulnerability detection
   - Cryptographic guarantees of contract safety

2. **Gas Optimization Through Proof**
   - Remove unnecessary runtime safety checks
   - Replace runtime validation with deployment-time proofs
   - Significant gas savings for proven-safe operations

3. **Compositional Verification**
   - Verify properties across multiple contracts
   - Protocol-level safety guarantees
   - Cross-contract invariant preservation

4. **Verifiable Results**
   - Anyone can independently verify proofs
   - No need to trust the analysis tool
   - Permanent proof of contract properties

## Recent Updates

### Accumulation-Based PCD Implementation

We've recently upgraded our Proof-Carrying Data (PCD) implementation to use the arkworks-rs/accumulation library, which provides a more efficient and flexible approach to accumulating proofs across multiple computations.

Key benefits of the new implementation:

- **Improved Efficiency**: The accumulation-based approach allows for more efficient verification of complex proof chains
- **Better Scalability**: Handles larger and more complex smart contracts with better performance
- **Enhanced Flexibility**: Supports a wider range of security properties and verification scenarios
- **Stronger Security Guarantees**: Provides even more robust mathematical guarantees about contract behavior

To use the new implementation, enable the `accumulation` feature flag:

```bash
cargo build --features accumulation
```

The new implementation is fully compatible with the existing API, so you can switch between implementations without changing your code.

## Running Tests

Run specific test suites:
```bash
# Run all tests
cargo test

# Run memory safety tests
cargo test -p evm-verify --test memory_patterns

# Run state transition tests
cargo test -p evm-verify --test state_transitions

# Run operation ordering tests
cargo test -p evm-verify --test operation_ordering
```

## Example Usage

```rust
use evm_verify::bytecode::BytecodeAnalyzer;
use ethers::core::types::Bytes;

// Load contract bytecode (e.g., from a compiled Solidity contract)
let bytecode = Bytes::from_hex("0x608060405234801561001057600080fd5b50...").unwrap();

// Create analyzer and run checks
let mut analyzer = BytecodeAnalyzer::new(bytecode);
let analysis = analyzer.analyze().expect("Analysis failed");

// Check for specific vulnerabilities
if analysis.has_reentrancy_vulnerability() {
    println!("⚠️ Warning: Contract may be vulnerable to reentrancy attacks");
}

// Get full vulnerability report
for vulnerability in analysis.get_vulnerability_report() {
    println!("Found vulnerability: {}", vulnerability);
}

// Check memory safety
if !analysis.is_memory_safe() {
    println!("⚠️ Warning: Unsafe memory operations detected");
}
```

## Unified API (New!)

The Unified API provides a comprehensive interface for analyzing Ethereum smart contracts using both Proof-Carrying Code (PCC) and Proof-Carrying Data (PCD) approaches.

```rust
use evm_verify::UnifiedVerifier;
use ethers::types::Bytes;

// Create a unified verifier
let verifier = UnifiedVerifier::new();

// Analyze bytecode
let bytecode = Bytes::from_hex("0x6001600055").unwrap(); // PUSH1 1 PUSH1 0 SSTORE
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

// Configure the verifier to use only PCC or PCD
let pcc_verifier = UnifiedVerifier::with_config(false, true); // PCC only
let pcd_verifier = UnifiedVerifier::with_config(true, false); // PCD only
```

For more details on the Unified API, see [README-unified-api.md](README-unified-api.md).

## Dependencies

- `ethers`: Ethereum types and utilities
- `anyhow`: Error handling
- `ark-ff`: Finite field arithmetic
- `revm`: EVM implementation

## License

MIT License
