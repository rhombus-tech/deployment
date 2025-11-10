# 🚀 Quick Start Guide - English Contracts

## **Convert Your Contract in 3 Steps**

### **1. Write Your Contract in English**

Create a text file `my_token.txt`:

```
CONTRACT: BasicToken
DESCRIPTION: A simple fungible token

FUNCTIONS:

1. FUNCTION: transfer
   PARAMETERS:
   - to: Address (Recipient)
   - amount: u64 (Amount to send)
   REQUIREMENTS:
   - Sender must have sufficient balance
   - Amount must be greater than zero
   DO:
   - Subtract amount from sender
   - Add amount to recipient
   - Return success
```

We've already created an example for you at:
```
examples/my_token_contract.txt
```

### **2. Set Your API Key**

```bash
export ANTHROPIC_API_KEY=sk-ant-your-key-here
```

Don't have one? Get it from: https://console.anthropic.com/

### **3. Run the Compiler**

```bash
cd /Users/talzisckind/Downloads/deployment/verify

# Build the tools
cargo build --release

# Compile your contract!
cargo run --bin english-contract -- \
  --input examples/my_token_contract.txt \
  --rust-output my_token.rs \
  --wasm-output my_token.wasm \
  --verbose

# You'll see:
# 🚀 Aristo English Contract Compiler
# ============================================================
# 
# 1️⃣  Parsing English contract...
#    ✅ Parsed: BasicToken
# 
# 2️⃣  Validating contract...
#    ✅ Validation passed
# 
# 3️⃣  Translating to Rust (using AI)...
#    ✅ Translation complete
# 
# 4️⃣  Compiling to WASM...
#    ✅ Compilation successful
# 
# 5️⃣  Running formal verification...
#    ✅ Verification PASSED
# 
# ✅ SUCCESS! Contract is ready for deployment
```

## **Output Files**

After running, you'll have:

- **`my_token.rs`** - Generated Rust source code
- **`my_token.wasm`** - Compiled WebAssembly bytecode (verified!)

## **Command-Line Options**

```bash
# Full compilation with verification
cargo run --bin english-contract -- --input contract.txt

# Save Rust code
cargo run --bin english-contract -- \
  --input contract.txt \
  --rust-output output.rs

# Save WASM bytecode
cargo run --bin english-contract -- \
  --input contract.txt \
  --wasm-output output.wasm

# Generate Rust only (skip compilation)
cargo run --bin english-contract -- \
  --input contract.txt \
  --rust-only

# Verbose output (see generated code)
cargo run --bin english-contract -- \
  --input contract.txt \
  --verbose

# Skip verification (faster, but not recommended)
cargo run --bin english-contract -- \
  --input contract.txt \
  --no-verify
```

## **What Gets Verified?**

Your WASM bytecode is automatically checked for:

✅ **Memory Safety** - No buffer overflows  
✅ **Type Safety** - No type confusion  
✅ **Bounds Checking** - All array accesses validated  
✅ **No Memory Leaks** - Proper resource cleanup  
✅ **Deterministic Execution** - Same input = same output  
✅ **Side-Channel Resistance** - Constant-time operations  
✅ **Parameter Validation** - Max 1024-byte inputs enforced  

## **Example Contracts**

We've included several templates:

```bash
# Simple token (ERC20-like)
examples/my_token_contract.txt

# See all examples in the documentation
cat ENGLISH_CONTRACTS.md
```

## **Troubleshooting**

### **"No API key found"**

```bash
# Make sure you've set the API key:
export ANTHROPIC_API_KEY=sk-ant-your-key-here

# Or add to your shell profile (~/.bashrc or ~/.zshrc):
echo 'export ANTHROPIC_API_KEY=sk-ant-your-key-here' >> ~/.zshrc
source ~/.zshrc
```

### **"Compilation failed"**

The AI-generated code has a syntax error. Try:

1. Check the generated Rust code with `--rust-output`
2. Simplify your English contract
3. Be more explicit in your requirements
4. Run with `--verbose` to see what was generated

### **"Verification failed"**

The contract doesn't meet safety requirements. This is GOOD - it caught a bug!

Common issues:
- Missing bounds checking
- Unsafe operations
- Non-deterministic behavior

Review the Rust code and adjust your English contract.

## **Next Steps**

1. **Try the examples**: Start with `examples/my_token_contract.txt`
2. **Read the guide**: Check `ENGLISH_CONTRACTS.md` for detailed docs
3. **Write your own**: Use the templates as a starting point
4. **Deploy**: Integrate the verified WASM into your blockchain

## **Full Documentation**

- `ENGLISH_CONTRACTS.md` - Complete guide with examples
- `README.md` - Your existing verification system docs
- `examples/` - Sample contracts

## **Support**

Questions? Check the documentation or review the example contracts.

---

**🎯 You're ready to write smart contracts in English!** 🚀
