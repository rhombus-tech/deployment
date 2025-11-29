#!/usr/bin/env bash
# Fractal Proving Network - One-Command Installer
# Trustless: Easy to run, no special hardware needed

set -e

echo "🚀 Fractal Proving Network Installer"
echo "======================================"
echo ""
echo "This installer will set up your proving node."
echo "Requirements: macOS or Linux, 4GB RAM, ~10GB disk space"
echo ""

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     MACHINE=Linux;;
    Darwin*)    MACHINE=Mac;;
    *)          MACHINE="UNKNOWN:${OS}"
esac

if [ "$MACHINE" = "UNKNOWN:${OS}" ]; then
    echo "❌ Unsupported operating system: ${OS}"
    exit 1
fi

echo "✅ Detected: ${MACHINE}"
echo ""

# Check for Rust
if ! command -v cargo &> /dev/null; then
    echo "📦 Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    echo "✅ Rust installed"
else
    echo "✅ Rust already installed"
fi

echo ""
echo "📥 Downloading Fractal Proving Network..."

# Clone or update repository
INSTALL_DIR="$HOME/.fractal-prover"
if [ -d "$INSTALL_DIR" ]; then
    echo "   Updating existing installation..."
    cd "$INSTALL_DIR"
    git pull
else
    echo "   Cloning repository..."
    git clone https://github.com/your-org/fractal-prover "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

echo ""
echo "🔨 Building prover (this may take a few minutes)..."
cd evm-verify
cargo build --release --bin production_fractal_prover

echo ""
echo "📝 Creating configuration..."

# Create config directory
CONFIG_DIR="$HOME/.config/fractal-prover"
mkdir -p "$CONFIG_DIR"

# Create default config if it doesn't exist
if [ ! -f "$CONFIG_DIR/config.toml" ]; then
    cat > "$CONFIG_DIR/config.toml" << 'EOF'
# Fractal Proving Network Configuration
# Trustless: You control your own settings

[network]
# Network to connect to (mainnet, sepolia, etc.)
chain_id = 1

# Your Ethereum address (to receive FRAC rewards)
# prover_address = "0x..."

[rpc]
# RPC endpoints (multiple for resilience!)
# Trustless: Add your own local node for maximum trustlessness
endpoints = [
    "http://localhost:8545",              # Your local node (BEST!)
    "https://eth.llamarpc.com",
    "https://rpc.ankr.com/eth",
    "https://ethereum.publicnode.com",
]

# Mark which endpoints are local (trusted)
local_endpoints = ["http://localhost:8545"]

[proving]
# Number of parallel proving tasks
workers = 4

# Task selection strategy
strategy = "phi_balanced"  # phi_balanced, random, greedy

[rewards]
# Reward strategy
strategy = "immediate"  # immediate, batched, confirmed

# For batched rewards
batch_size = 10
batch_interval_seconds = 300
EOF
    echo "✅ Created default config at: $CONFIG_DIR/config.toml"
    echo ""
    echo "⚙️  Edit this file to customize your prover"
else
    echo "✅ Using existing config: $CONFIG_DIR/config.toml"
fi

# Create launcher script
LAUNCHER="$HOME/.local/bin/fractal-prover"
mkdir -p "$HOME/.local/bin"

cat > "$LAUNCHER" << EOF
#!/usr/bin/env bash
# Fractal Prover Launcher
cd "$INSTALL_DIR/evm-verify"
exec ./target/release/production_fractal_prover --config "$CONFIG_DIR/config.toml" "\$@"
EOF

chmod +x "$LAUNCHER"

echo ""
echo "✅ Installation complete!"
echo ""
echo "======================================"
echo "🎯 How to start proving:"
echo "======================================"
echo ""
echo "1. Edit your config (optional):"
echo "   nano $CONFIG_DIR/config.toml"
echo ""
echo "2. Start proving:"
echo "   fractal-prover start"
echo ""
echo "3. Check status:"
echo "   fractal-prover status"
echo ""
echo "======================================"
echo "💡 Tips for maximum trustlessness:"
echo "======================================"
echo ""
echo "🔹 Run a local Ethereum node (most trustless!):"
echo "   - Geth: https://geth.ethereum.org/"
echo "   - Reth: https://reth.rs/"
echo "   - Erigon: https://github.com/ledgerwatch/erigon"
echo ""
echo "🔹 Add your own RPC endpoints to the config"
echo ""
echo "🔹 Join our community:"
echo "   - Discord: https://discord.gg/fractal-prover"
echo "   - GitHub: https://github.com/your-org/fractal-prover"
echo ""
echo "======================================"
echo ""
echo "Happy proving! 🚀"
