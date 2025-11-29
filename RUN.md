# Run Fractal Network

## Test Everything
```bash
./test_everything.sh
```

## Run Production Node
```bash
cd evm-verify
cargo run --release --example production_fractal_node
```

## Deploy Smart Contracts
```bash
# 1. Deploy FRAC token
# 2. Deploy distribution contract
# 3. Deploy reward pool
# 4. Deploy registry
# 5. Grant minting rights to reward pool
# 6. Launch token distribution
```

## Environment Variables
```bash
export ETH_RPC_URL="https://eth.llamarpc.com"
export FRAC_TOKEN="0x..."
export REWARD_POOL="0x..."
export REGISTRY_CONTRACT="0x..."
export PRIVATE_KEY="your_key"
```

## Start Earning FRAC
```bash
# Run node, generate proofs, earn FRAC tokens
# 10-30 FRAC per proof depending on quality/speed
# See TOKENOMICS.md for details
```

## Monitor
- Metrics: `http://localhost:9090/metrics`
- JSON: `http://localhost:9090/metrics.json`
- Health: `http://localhost:9090/health`
