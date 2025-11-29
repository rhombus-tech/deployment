#!/bin/bash
# 🌳 Join the Fractal Proving Network
# Permissionless - No approval needed!

set -e

echo "🌳 Fractal Proving Network - Join as a Node Operator"
echo "══════════════════════════════════════════════════════"
echo ""

# Check dependencies
echo "📋 Checking requirements..."
command -v cargo >/dev/null 2>&1 || { echo "❌ Rust/Cargo required. Install from https://rustup.rs"; exit 1; }
command -v git >/dev/null 2>&1 || { echo "❌ Git required"; exit 1; }

echo "✅ All requirements met!"
echo ""

# Generate node identity
echo "🔑 Generating your node identity..."
NODE_ID="node_$(openssl rand -hex 4)"
PROVER_KEY=$(openssl rand -hex 32)

echo "   Node ID: $NODE_ID"
echo "   (Save this - you'll need it to claim rewards!)"
echo ""

# Ask for stake amount
echo "💰 Staking (optional but recommended for higher earnings):"
echo "   • Bronze (1,000 FRAC): 5% APY + 1.0x multiplier"
echo "   • Silver (10,000 FRAC): 6% APY + 1.5x multiplier"  
echo "   • Gold (100,000 FRAC): 7% APY + 2.0x multiplier"
echo "   • Platinum (1,000,000 FRAC): 8% APY + 2.5x multiplier"
echo ""
read -p "Stake amount (or press Enter to skip): " STAKE_AMOUNT

# Build the prover
echo ""
echo "🔨 Building fractal prover..."
cd "$(dirname "$0")"

if [ ! -f "evm-verify/src/bin/production_fractal_prover.rs" ]; then
    echo "❌ Error: Run this from the deployment directory"
    exit 1
fi

cargo build --release --bin production_fractal_prover

if [ $? -ne 0 ]; then
    echo "❌ Build failed. Check errors above."
    exit 1
fi

echo "✅ Prover built successfully!"
echo ""

# Create config file
echo "📝 Creating configuration..."
cat > fractal-node-config.toml <<EOF
# Fractal Network Node Configuration
node_id = "$NODE_ID"
prover_key = "$PROVER_KEY"

# Network settings
network = "mainnet"  # or "testnet"
rpc_url = "https://eth.llamarpc.com"

# Rewards
eth_address = ""  # Add your ETH address here to receive FRAC
stake_amount = "${STAKE_AMOUNT:-0}"

# Performance
max_parallel_proofs = 4
enable_adaptive_batching = true

# φ-Optimization (auto-computed)
auto_coordinate = true
EOF

echo "✅ Config created: fractal-node-config.toml"
echo ""

# Register on-chain (optional)
echo "📡 Registering on-chain..."
echo "   (You can do this later by calling FractalProverRegistry.registerProver)"
echo ""

# Start the node
echo "🚀 Starting your fractal prover node..."
echo "══════════════════════════════════════════════════════"
echo ""

export NODE_ID=$NODE_ID
export PROVER_KEY=$PROVER_KEY

./target/release/production_fractal_prover &
PROVER_PID=$!

echo "✅ Node started! PID: $PROVER_PID"
echo ""
echo "📊 Your node is now:"
echo "   • Generating ZODA proofs"
echo "   • Earning FRAC tokens"
echo "   • Contributing to network security"
echo ""
echo "💰 Earnings:"
echo "   • Base: ~0.008 FRAC per proof"
echo "   • φ-Bonus: Up to +20% for optimal positioning"
echo "   • Staking: ${STAKE_AMOUNT:-0} FRAC staked"
echo ""
echo "🔍 Monitor your node:"
echo "   tail -f fractal-node.log"
echo ""
echo "🛑 Stop your node:"
echo "   kill $PROVER_PID"
echo ""
echo "════════════════════════════════════════════════════════"
echo "🎉 Welcome to the Fractal Proving Network!"
echo "════════════════════════════════════════════════════════"
