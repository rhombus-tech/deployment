# 🚀 Complete FRAC Desktop App - Setup Instructions

## Quick Start (5 minutes)

### 1. Create Tauri Project

```bash
cd /Users/talzisckind/Downloads/deployment

# Install Tauri CLI if not already installed
cargo install tauri-cli --version "^2.0.0-rc"

# Create new Tauri app
npm create tauri-app@latest

# When prompted:
# - App name: frac-prover
# - Package manager: npm  
# - UI template: React
# - Add TypeScript? Yes
# - Add Tailwind? Yes

cd frac-prover
```

### 2. Install Dependencies

```bash
npm install

# Additional packages for UI
npm install framer-motion lucide-react recharts
npm install @tanstack/react-query date-fns
```

### 3. Copy Backend Code

```bash
# Copy the gui_prover.rs to Tauri src
cp ../evm-verify/src/bin/gui_prover.rs src-tauri/src/

# Update src-tauri/src/main.rs (see below)
```

### 4. Run Development Server

```bash
npm run tauri dev
```

### 5. Build for Production

```bash
npm run tauri build

# Creates installers:
# - macOS: src-tauri/target/release/bundle/dmg/
# - Windows: src-tauri/target/release/bundle/msi/
# - Linux: src-tauri/target/release/bundle/appimage/
```

---

## File Structure

```
frac-prover/
├── src/                          # React Frontend
│   ├── App.tsx
│   ├── components/
│   │   ├── Dashboard.tsx
│   │   ├── EarningsChart.tsx
│   │   ├── ActivityFeed.tsx
│   │   ├── StatusCard.tsx
│   │   └── Settings.tsx
│   ├── hooks/
│   │   └── useProver.ts
│   ├── lib/
│   │   └── tauri.ts
│   └── styles/
│       └── globals.css
│
├── src-tauri/                    # Rust Backend
│   ├── src/
│   │   ├── main.rs              # Tauri entry point
│   │   ├── gui_prover.rs        # Our prover backend
│   │   └── lib.rs
│   ├── Cargo.toml
│   └── tauri.conf.json
│
├── public/
│   └── icons/                   # App icons
│
├── package.json
├── tailwind.config.js
└── tsconfig.json
```

---

## Complete Code Files Below ⬇️

I'll provide each file in sequence...
