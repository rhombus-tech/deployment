# 📝 English Contract System

Write smart contracts in **plain English**, compile to **WASM**, and get **formal verification** - all in one pipeline.

## 🎯 Overview

The English Contract System allows developers to write blockchain smart contracts in natural language, which are then:

1. **Translated** to Rust code using AI (Claude/GPT)
2. **Compiled** to WebAssembly bytecode
3. **Verified** using formal verification (PCC/PCD)
4. **Deployed** to your blockchain

## 🚀 Quick Start

### Prerequisites

```bash
# 1. Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Add WASM target
rustup target add wasm32-unknown-unknown

# 3. Set API key (for AI translation)
export ANTHROPIC_API_KEY=your_key_here
```

### Run the Demo

```bash
cd /Users/talzisckind/Downloads/deployment/verify

# Build the project
cargo build --release

# Run the English contract demo
cargo run --bin english_contract_demo

# You'll see:
# 🚀 Aristo English Contract Translation Demo
# ============================================================
# 
# 📝 ENGLISH CONTRACT SPECIFICATION:
# Name: SimpleToken
# Functions: 2
#   1. transfer (to: Address, amount: u64)
#   2. balance_of (account: Address)
# 
# ⚙️  TRANSLATION PIPELINE:
# 1️⃣  Initializing pipeline...
#    ✅ Pipeline ready
# 2️⃣  Validating English contract...
#    ✅ Validation passed
# 3️⃣  Translating to Rust code (using AI)...
#    🤖 Calling Claude API...
#    ✅ Translation complete
# 4️⃣  Compiling Rust to WASM...
#    ✅ Compilation successful
# 5️⃣  Verifying WASM with formal verification...
#    ✅ WASM validation passed
# 
# ✅ SUCCESS! Contract ready for deployment!
```

## 📖 Writing English Contracts

### Basic Structure

```
CONTRACT: YourContractName
DESCRIPTION: Brief description of what your contract does

CONFIGURATION:
- key: value
- another_key: another_value

STATE VARIABLES:
- variable_name: type (description)
- balances: HashMap<Address, u64> (User token balances)

FUNCTIONS:

1. FUNCTION: function_name
   PARAMETERS:
   - param_name: type (description)
   - amount: u64 (Amount to transfer)
   
   RETURNS:
   - type: description
   - bool: Success status
   
   REQUIREMENTS:
   - Requirement 1
   - Sender must be authorized
   - Amount must be positive
   
   DO:
   - Step 1
   - Validate parameters
   - Perform action
   - Return result

EVENTS:
- EventName (param1: type, param2: type)
```

### Example: Simple Token

```
CONTRACT: SimpleToken
DESCRIPTION: A basic fungible token with transfer functionality

CONFIGURATION:
- total_supply: 1000000
- decimals: 18

STATE VARIABLES:
- balances: HashMap<Address, u64> (Token balances)
- total_supply: u64 (Total token supply)
- owner: Address (Contract owner)

FUNCTIONS:

1. FUNCTION: transfer
   PARAMETERS:
   - to: Address (Recipient address)
   - amount: u64 (Amount to transfer)
   
   RETURNS:
   - bool: Success status
   
   REQUIREMENTS:
   - Sender must have at least {amount} tokens
   - Recipient address cannot be zero
   - Amount must be greater than zero
   
   DO:
   - Validate parameters (bounds check: max 1024 bytes)
   - Get sender address from context
   - Check sender has sufficient balance
   - Subtract {amount} from sender's balance
   - Add {amount} to recipient's balance
   - Emit Transfer event
   - Return true for success

2. FUNCTION: balance_of
   PARAMETERS:
   - account: Address (Address to check)
   
   RETURNS:
   - u64: Token balance
   
   DO:
   - Look up balance in balances mapping
   - Return balance (or 0 if not found)

EVENTS:
- Transfer (from: Address, to: Address, amount: u64)
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  1. ENGLISH INPUT                                            │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ CONTRACT: MyToken                                      │ │
│  │ FUNCTION: transfer                                     │ │
│  │   REQUIREMENTS:                                        │ │
│  │   - Sender must have balance                           │ │
│  │   DO:                                                  │ │
│  │   - Transfer tokens                                    │ │
│  └────────────────────────────────────────────────────────┘ │
│                       ↓                                      │
│  [Parser] → EnglishContract struct                          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  2. VALIDATION                                               │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ • Contract structure validated                         │ │
│  │ • Security requirements checked                        │ │
│  │ • Reentrancy risks detected                            │ │
│  │ • Access control verified                              │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  3. AI TRANSLATION (IN TEE)                                 │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ #[no_mangle]                                           │ │
│  │ pub extern "C" fn transfer(                            │ │
│  │     params: *const u8                                  │ │
│  │ ) -> bool {                                            │ │
│  │     // AI-generated Rust code                          │ │
│  │     // with proper bounds checking                     │ │
│  │     true                                                │ │
│  │ }                                                       │ │
│  └────────────────────────────────────────────────────────┘ │
│                       ↓                                      │
│  [LLM Translator] → Rust source code                        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  4. COMPILATION                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ cargo build --target wasm32-unknown-unknown            │ │
│  └────────────────────────────────────────────────────────┘ │
│                       ↓                                      │
│  [Rust Compiler] → WASM bytecode                            │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  5. FORMAL VERIFICATION ✅ (YOUR EXISTING SYSTEM)           │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ ✓ Memory safety (bounds checking)                     │ │
│  │ ✓ Type safety                                          │ │
│  │ ✓ Resource bounds                                      │ │
│  │ ✓ Determinism                                          │ │
│  │ ✓ Side-channel resistance                              │ │
│  │ ✓ Parameter validation (1024-byte limit)              │ │
│  └────────────────────────────────────────────────────────┘ │
│                       ↓                                      │
│  [Your Verifier] → VerificationProof                        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  6. DEPLOYMENT                                               │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ • WASM bytecode stored on blockchain                   │ │
│  │ • Verification proof attached                          │ │
│  │ • Contract address assigned                            │ │
│  │ • Ready for execution in TEE                           │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## 🔒 Security Features

### Built-in Safety

Your existing verification system ensures:

- ✅ **Memory Safety**: All memory accesses bounds-checked
- ✅ **Type Safety**: No type confusion or invalid casts  
- ✅ **Parameter Validation**: Max 1024-byte input enforced
- ✅ **No Panic**: Graceful error handling
- ✅ **Deterministic**: No random, no system calls
- ✅ **Side-Channel Resistant**: Constant-time operations

### AI-Generated Code Validation

Additional checks on LLM output:

- ✅ Required `#[no_mangle]` attribute present
- ✅ Required `extern "C"` declaration present
- ✅ No `unsafe` blocks
- ✅ No filesystem operations (`std::fs`)
- ✅ No network operations (`std::net`)
- ✅ No random operations (`rand::`)
- ✅ Balanced braces/brackets

### English Contract Validation

Before translation:

- ✅ Reentrancy risk detection
- ✅ Access control checks
- ✅ Dangerous pattern warnings
- ✅ Missing security requirements flagged

## 🎨 Example Contracts

### 1. Simple Token (ERC20-like)

See example above.

### 2. Escrow Contract

```
CONTRACT: SimpleEscrow
DESCRIPTION: Trustless escrow with dispute resolution

STATE VARIABLES:
- escrows: HashMap<u64, Escrow> (All escrows)
- next_id: u64 (Next escrow ID)

FUNCTIONS:

1. FUNCTION: create_escrow
   PARAMETERS:
   - seller: Address (Seller address)
   - description: String (Item description)
   
   REQUIREMENTS:
   - Amount must be greater than zero
   - Seller cannot be buyer
   
   DO:
   - Create new escrow with unique ID
   - Store buyer, seller, amount
   - Set status to "Pending"
   - Return escrow ID

2. FUNCTION: complete_escrow
   PARAMETERS:
   - escrow_id: u64 (Escrow to complete)
   
   REQUIREMENTS:
   - Only buyer can call this
   - Escrow must be "Pending"
   
   DO:
   - Transfer funds to seller
   - Set status to "Completed"
   - Return success
```

### 3. DAO Voting

```
CONTRACT: SimpleDAO
DESCRIPTION: Decentralized autonomous organization

CONFIGURATION:
- voting_period: 259200
- quorum: 10

STATE VARIABLES:
- proposals: HashMap<u64, Proposal> (All proposals)
- votes: HashMap<u64, HashMap<Address, Vote>> (Votes by proposal)

FUNCTIONS:

1. FUNCTION: create_proposal
   PARAMETERS:
   - title: String (Proposal title)
   - description: String (Detailed description)
   
   REQUIREMENTS:
   - Caller must hold governance tokens
   
   DO:
   - Create proposal with unique ID
   - Set voting period
   - Return proposal ID

2. FUNCTION: vote
   PARAMETERS:
   - proposal_id: u64 (Proposal to vote on)
   - vote_choice: String ("Yes", "No", "Abstain")
   
   REQUIREMENTS:
   - Proposal must be active
   - Caller must hold governance tokens
   - Caller has not already voted
   
   DO:
   - Record vote with token weight
   - Update vote tallies
   - Return success
```

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run English module tests
cargo test --lib english

# Run demo with different API key
ANTHROPIC_API_KEY=sk-... cargo run --bin english_contract_demo

# Test with custom contract
cargo run --bin english_contract_demo -- --contract my_contract.txt
```

## 📊 Benefits

### For Developers

- **No Rust Knowledge Required**: Write contracts in English
- **Rapid Prototyping**: Iterate on contract logic quickly  
- **Built-in Security**: Formal verification catches bugs
- **No Deployment Surprises**: Verification happens before deploy

### For Auditors

- **Human-Readable Spec**: English source is easy to audit
- **Provable Safety**: Mathematical proofs of security properties
- **Full Traceability**: English → Rust → WASM chain preserved

### For Users

- **Transparent Logic**: Can read what contract does in English
- **Guaranteed Safety**: Verified contracts can't have certain bugs
- **Trust**: Formal proofs > manual audits

## 🔮 Future Enhancements

- [ ] **Web IDE**: Browser-based contract editor
- [ ] **Template Library**: Pre-built contract templates
- [ ] **Interactive Debugging**: Step through English logic
- [ ] **Multi-Language**: Support languages beyond English
- [ ] **TEE Integration**: Run AI translation inside TEE
- [ ] **Gas Estimation**: Predict execution costs
- [ ] **Upgrade Patterns**: Safe contract upgrade mechanisms

## 🤝 Contributing

This system integrates with your existing verification pipeline at:

- `verify/src/english/` - English contract modules
- `verify/src/lib.rs` - Main library integration
- `verify/examples/` - Example contracts

To add new features:

1. Extend `EnglishContract` struct for new syntax
2. Update `LLMTranslator` prompts for better code generation
3. Add validation rules in `ContractValidator`
4. Test with `cargo test --lib english`

## 📚 Learn More

- [Verification System README](README.md) - Your existing WASM verifier
- [Proof-Carrying Code (PCC)](https://en.wikipedia.org/wiki/Proof-carrying_code)
- [WebAssembly](https://webassembly.org/)
- [Rust WASM Book](https://rustwasm.github.io/docs/book/)

## 🎯 Next Steps

1. **Try the demo**: `cargo run --bin english_contract_demo`
2. **Write your own contract**: Use the templates above
3. **Integrate with deployment**: Add to your blockchain pipeline
4. **Build a UI**: Create web interface for non-developers

---

**Built on top of your production-ready WASM verification system** 🚀
