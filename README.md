# WASM Contract Verification System

A deployment-time verification system that combines Proof-Carrying Code (PCC) and Proof-Carrying Data (PCD) to verify crucial safety properties of WASM contracts before deployment.

## 💡 Why Rust + Verification?

Our system provides strong safety guarantees while letting you use the full power of Rust:

### Safety Without Sacrifice
- Type safety verification
- Resource usage control
- Linear type guarantees
All without leaving the Rust ecosystem.

### Benefits Over Restricted Languages
- Use any Rust library
- Mature tooling and ecosystem
- Larger developer pool
- More expressive power
- Custom property verification

No need to learn a new language or accept limitations - get safety guarantees while keeping Rust's flexibility.

## 🛡️ Safety Properties Verified

While Rust's compiler provides excellent safety guarantees, our system adds Move-like verification at deployment time:

### Type Safety Properties
- **Linear Types**: Verify resources can't be copied or discarded
- **Type Constraints**: Ensure type rules are followed
- **Resource Types**: Verify proper resource handling
- **Type State**: Track type state transitions

### Resource Properties
- **Resource Tracking**: Verify resources are never duplicated or lost
- **Usage Patterns**: Ensure resources are properly consumed
- **Lifecycle Management**: Track resource creation to destruction
- **Access Control**: Verify proper resource ownership

### State Properties
- **State Transitions**: Verify valid state changes
- **Invariants**: Maintain system invariants
- **Computation Steps**: Verify computation validity
- **Safety Rules**: Enforce safety properties

### Protocol Properties
- **Protocol Rules**: Verify compliance with rules
- **Safety Properties**: Enforce safety constraints
- **Computation Validity**: Verify correct behavior
- **Invariant Preservation**: Maintain system invariants

The system provides Move-like guarantees while allowing full use of Rust's ecosystem and expressiveness.

## 📚 Core Technology

### Proof-Carrying Code (PCC)
A formal verification technique where code includes mathematical proofs about its behavior[^1]. Used to verify:
- Specific safety properties (e.g., memory bounds)
- Resource usage constraints
- Compliance with protocol rules

### Proof-Carrying Data (PCD)
A technique for proving properties about computation steps[^1]. Used to verify:
- Each computation step is valid
- Results maintain required properties
- Proofs can be verified independently

Together, these provide strong guarantees about both code behavior and data flow.

## 🚀 Deployment Process

### 1. Proof Generation
When you deploy a WASM contract, the system:
- Analyzes the contract code
- Generates safety proofs (PCC)
- Creates computation proofs (PCD)
- Builds verification circuits

### 2. Verification
The system verifies:
- Safety properties
- Resource constraints
- Computation correctness
- Protocol compliance

### 3. Results
You get one of two outcomes:

**✅ Success**
- All proofs verify
- Properties hold
- Contract is safe
- Deployment proceeds

**❌ Failure**
- Shows verification failures
- Points to issues
- Explains problems
- Blocks deployment

## 🛣️ Roadmap

[Coming soon]

## 🔧 Development

### Prerequisites
- Rust toolchain
- arkworks dependencies

### Building
```bash
cargo build --release
```

[^1]: Alessandro Chiesa, ["Proof-Carrying Data"](https://dspace.mit.edu/bitstream/handle/1721.1/61151/698133641-MIT.pdf), MIT PhD Thesis, 2010.
