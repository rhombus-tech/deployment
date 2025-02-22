# EVM Verify

A zero-knowledge proof system for verifying Ethereum smart contract deployments.

## Overview

This system provides cryptographic guarantees about smart contract deployments by generating and verifying zero-knowledge proofs that ensure:

1. Bytecode correctness and integrity
2. Constructor argument validation
3. Storage initialization verification
4. Access control setup verification
5. Security pattern compliance

## Project Structure

- `common/`: Shared utilities and types
- `circuits/`: Zero-knowledge circuits for EVM verification
- `prover/`: Proof generation and verification system
- `example/`: Example contracts and deployment verification

## Getting Started

```bash
# Build the project
cargo build

# Run tests
cargo test

# Run example verification
cargo run --example verify_deployment
```

## Dependencies

- Ethereum: ethers, web3, revm
- ZK Proof Systems: arkworks suite
- Utilities: anyhow, tracing

## License

MIT License
