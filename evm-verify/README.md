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

EVM Verify uses formal methods to prove properties about smart contract bytecode, ensuring security and correctness. Unlike traditional security tools that look for known vulnerability patterns, formal verification mathematically proves that certain properties must hold true for all possible executions of the contract.

For example, instead of just checking if a contract might have reentrancy, we prove that reentrancy is impossible by showing that no execution path can violate our security properties. This means:

- **Completeness**: We analyze all possible execution paths, not just common cases
- **Mathematical Proof**: Properties are proven to be true, not just likely or suggested
- **Zero False Negatives**: If we prove a property, it's guaranteed to hold
- **Compile-Time Guarantees**: Issues are caught before deployment, not at runtime

## Comparison with Other Tools

| Feature | EVM Verify | Traditional Auditing | Static Analyzers | Symbolic Execution |
|---------|------------|---------------------|------------------|-------------------|
| **Analysis Type** | Formal Verification | Expert Review | Pattern Matching | Path Exploration |
| **Coverage** | Property-Specific | Comprehensive | Known Patterns | Path-Limited |
| **False Positives** | Very Low | Analyst Dependent | Common | Common |
| **False Negatives** | Property-Dependent | Possible | Common | Path-Dependent |
| **Gas Analysis** | Safety Proofs | Manual Review | Basic Checks | Path-Based |
| **Time to Results** | Minutes to Hours | Days/Weeks | Minutes | Hours |
| **Scope** | Contract-Level | Protocol-Level | Contract-Level | Function-Level |

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

## Dependencies

- `ethers`: Ethereum types and utilities
- `anyhow`: Error handling
- `ark-ff`: Finite field arithmetic
- `revm`: EVM implementation

## License

MIT License
