# 🏠 Local zkEVM Testing Setup

Run the same zkEVM proving system locally that's running on AWS.

## 🚀 Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/rhombus-tech/deployment.git
cd deployment
```

### 2. Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup default stable
```

### 3. Set Environment Variable
```bash
# Recommended: Get free API key from Alchemy
export ETH_RPC_URL="https://eth-mainnet.g.alchemy.com/v2/YOUR_ALCHEMY_KEY"

# Alternative public RPCs (may have rate limits):
# export ETH_RPC_URL="https://eth.llamarpc.com"
# export ETH_RPC_URL="https://ethereum-rpc.publicnode.com"
# export ETH_RPC_URL="https://rpc.ankr.com/eth"
```

### 4. Run the Live Proving Service
```bash
cd evm-verify
cargo run --bin live-proving-service --release
```

## 🌐 Available Services

### **Live Proving Service** (Recommended)
Same service running on AWS - proves blocks on-demand:
```bash
cargo run --bin live-proving-service --release
```
- **Web UI**: http://localhost:8081
- **Status**: http://localhost:8081/status
- **Challenge**: http://localhost:8081/api/challenge/BLOCK_NUMBER

### **Simple Production Server**
Lightweight version:
```bash
cargo run --bin simple_production_server --release
```

### **Unified Service** 
Full-featured with all APIs:
```bash
cargo run --bin unified_service --release
```

## 🧪 Test the Service

### Check Status
```bash
curl http://localhost:8081/status
```

### Run a Block Challenge
```bash
curl http://localhost:8081/api/challenge/23060000
```

### Performance Test
```bash
# Edit quick_test.sh to use localhost:8081 instead of zk-evm.org
./quick_test.sh
```

## 🎯 Endpoints Available

| Endpoint | Description |
|----------|-------------|
| `/` | Demo web interface |
| `/status` | Service health & metrics |
| `/api/challenge/{block}` | Prove specific block |
| `/results` | Recent proof results |
| `/health` | Health check |
| `/metrics` | Performance metrics |

## ⚡ Performance Expectations

- **First proof**: ~30-60 seconds (system warmup)
- **Subsequent proofs**: ~100-200ms average
- **Memory usage**: ~2-4GB RAM
- **CPU**: Multi-core recommended

## 🔧 Configuration

### Custom RPC Endpoint
```bash
export ETH_RPC_URL="your-ethereum-rpc-url"
```

### Custom Port
```bash
export PORT=3000  # Default is 8081
```

### Debug Mode
```bash
export RUST_LOG=debug
```

## 🐛 Troubleshooting

### Service Won't Start
- Check Rust installation: `rustc --version`
- Verify RPC URL is accessible: `curl $ETH_RPC_URL`
- Check port availability: `lsof -i :8081`

### RPC Connection Issues
If you see `"error decoding response body: expected value at line 1 column 1"`:

```bash
# Test your RPC endpoint
curl -X POST $ETH_RPC_URL \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

**Solutions:**
- Use Alchemy (free tier): `https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY`
- Try different public RPC: `https://ethereum-rpc.publicnode.com`
- Check rate limits on free RPCs

### Slow Performance
- Ensure release mode: `--release` flag
- Check system resources: `htop`
- Verify RPC response time: `time curl $ETH_RPC_URL`

### Build Errors
```bash
# Update toolchain
rustup update

# Clean build
cargo clean
cargo build --release
```

## 📊 Monitor Performance

### Real-time Status
```bash
# On macOS, install watch: brew install watch
watch -n 5 'curl -s localhost:8081/status | jq .'
```

### Load Testing
```bash
# Test multiple block challenges
for i in {23060000..23060010}; do
  time curl -s "localhost:8081/api/challenge/$i" | jq '.proving_time_ms'
done
```

Now you can run the exact same zkEVM proving system locally that powers **zk-evm.org**! 🎉
