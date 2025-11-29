# Trustless WASM Bindings

WebAssembly bindings that bridge the TypeScript SDK to Rust proving code.

## 🎯 Purpose

This crate compiles your existing `evm-verify` and `stateless-vm` Rust code into WebAssembly that can be called from JavaScript.

## 🏗️ Architecture

```
TypeScript (@trustless/sdk)
    ↓
trustless-wasm (this crate)
    ↓
┌─────────────────────────────┐
│ evm-verify                  │
│ - ZODA proving              │
│ - WARP accumulation         │
│ - Security analysis         │
└─────────────────────────────┘
    ↓
┌─────────────────────────────┐
│ stateless-vm                │
│ - Atomic execution          │
│ - State management          │
│ - DeFi protection           │
└─────────────────────────────┘
```

## 📦 Building

### Prerequisites

```bash
# Install wasm-pack
cargo install wasm-pack

# Install Node.js (if not already installed)
# brew install node  # macOS
```

### Build Commands

```bash
# Build for web (browser)
wasm-pack build --target web --out-dir ../trustless-sdk/wasm

# Build for Node.js
wasm-pack build --target nodejs --out-dir ../trustless-sdk/wasm-node

# Build with optimizations (production)
wasm-pack build --target web --release --out-dir ../trustless-sdk/wasm
```

### Build Output

After building, you'll have:

```
../trustless-sdk/wasm/
├── trustless_wasm.js        # JavaScript wrapper
├── trustless_wasm_bg.wasm   # WebAssembly binary
├── trustless_wasm.d.ts      # TypeScript definitions
└── package.json             # Package metadata
```

## 🔌 Integration

### Current Status (Simulated)

The current implementation uses **simulation** functions:
- `simulate_prove()` - Returns fake proof
- `simulate_security_analysis()` - Returns fake analysis
- `simulate_atomic_bundle()` - Returns fake bundle
- `simulate_compression()` - Returns fake compression

### TODO: Wire Up Real Implementation

Replace simulation with real calls:

#### 1. Proving (`prove_transaction`)

```rust
// Current (simulation):
let proof = simulate_prove(&tx).await?;

// TODO (real implementation):
use evm_verify::api::hybrid_zoda_warp_strategy::ZodaWarpHybridStrategy;

let strategy = ZodaWarpHybridStrategy::new_for_consumer_hardware()?;
let proof = strategy.prove_transaction(&tx).await?;
```

#### 2. Security Analysis (`analyze_security`)

```rust
// Current (simulation):
let analysis = simulate_security_analysis(bytecode).await?;

// TODO (real implementation):
use evm_verify::bytecode::vulnerability_detector::VulnerabilityDetector;

let detector = VulnerabilityDetector::new();
let analysis = detector.analyze(bytecode)?;
```

#### 3. Atomic Execution (`create_atomic_bundle`)

```rust
// Current (simulation):
let bundle = simulate_atomic_bundle(operations).await?;

// TODO (real implementation):
use stateless_vm::atomic::AtomicExecutor;

let executor = AtomicExecutor::new(config)?;
let bundle = executor.create_bundle(operations).await?;
```

#### 4. WARP Compression (`compress_proofs`)

```rust
// Current (simulation):
let compressed = simulate_compression(proofs).await?;

// TODO (real implementation):
use evm_verify::accumulation::warp::WarpAccumulator;

let accumulator = WarpAccumulator::new()?;
let compressed = accumulator.compress(proofs).await?;
```

## 🧪 Testing

```bash
# Run WASM tests
wasm-pack test --headless --chrome

# Run with Firefox
wasm-pack test --headless --firefox

# Run with Safari
wasm-pack test --headless --safari
```

## 📏 Size Optimization

The release build is optimized for size:

- `opt-level = "z"` - Optimize for size
- `lto = true` - Link-time optimization
- `strip = true` - Strip debug symbols

Typical sizes:
- **Debug build**: ~2-3 MB
- **Release build**: ~500-800 KB
- **With compression**: ~150-250 KB (gzipped)

## 🚀 Performance

Expected performance on consumer hardware:

| Operation | Time | Notes |
|-----------|------|-------|
| Proving | 11-25ms | ZODA with WARP |
| Security Analysis | < 100ms | 23 vulnerability types |
| Atomic Bundle | < 50ms | Multi-transaction |
| WARP Compression | < 30ms | 10x compression |

## 📝 Functions Exported

### `prove_transaction(tx_bytes: &[u8]) -> Vec<u8>`
Generates a ZK proof for a transaction.

**Input**: JSON-serialized transaction
**Output**: Binary proof data

### `verify_proof(proof: &[u8]) -> bool`
Verifies a ZK proof.

**Input**: Binary proof data
**Output**: Verification result

### `analyze_security(bytecode: &[u8]) -> Vec<u8>`
Analyzes contract bytecode for vulnerabilities.

**Input**: Contract bytecode
**Output**: JSON-serialized security analysis

### `create_atomic_bundle(operations: &[u8]) -> Vec<u8>`
Creates an atomic multi-transaction bundle.

**Input**: JSON-serialized operations
**Output**: Binary atomic bundle

### `compress_proofs(proofs: &[u8]) -> Vec<u8>`
Compresses multiple proofs using WARP.

**Input**: Multiple proof data
**Output**: Compressed proof data

## 🔧 Development Workflow

### 1. Make Changes

Edit `src/lib.rs` to add new functions or modify existing ones.

### 2. Build

```bash
wasm-pack build --target web --out-dir ../trustless-sdk/wasm
```

### 3. Test in TypeScript

```bash
cd ../trustless-sdk
npm run dev  # Starts watch mode
```

### 4. Iterate

The TypeScript SDK will automatically pick up changes to the WASM module.

## 📚 Resources

- [wasm-bindgen Book](https://rustwasm.github.io/docs/wasm-bindgen/)
- [wasm-pack Guide](https://rustwasm.github.io/docs/wasm-pack/)
- [WebAssembly Reference](https://webassembly.org/)

## 🐛 Troubleshooting

### "Cannot find module" error

Make sure you built the WASM:
```bash
npm run build:wasm
```

### Size too large

Use release build with optimizations:
```bash
wasm-pack build --target web --release
```

### Performance issues

Check that you're using release mode and that the WASM is being loaded correctly.
