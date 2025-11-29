#!/bin/bash
# FRAC Desktop App - One Command Setup

echo "💎 Setting up FRAC Prover Desktop App..."
echo ""

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "❌ npm not found. Install Node.js first: https://nodejs.org/"
    exit 1
fi

# Check if cargo is installed  
if ! command -v cargo &> /dev/null; then
    echo "❌ cargo not found. Install Rust first: https://rustup.rs/"
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Install Tauri CLI
echo "🦀 Installing Tauri CLI..."
cargo install tauri-cli --version "^2.0.0-rc"

# Copy backend code from evm-verify
echo "📋 Setting up backend..."
mkdir -p src-tauri/src
cp ../evm-verify/src/bin/gui_prover.rs src-tauri/src/ 2>/dev/null || echo "⚠️  gui_prover.rs not found (will need to create manually)"

echo ""
echo "✅ Setup complete!"
echo ""
echo "🚀 To run:"
echo "   npm run tauri:dev"
echo ""
echo "📦 To build:"
echo "   npm run tauri:build"
