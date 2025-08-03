const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
    console.log("Deploying VerifiedAtomicExecutor with PCC Verifier integration...");
    
    const [deployer] = await ethers.getSigners();
    console.log("Deploying contracts with account:", deployer.address);
    const balance = await ethers.provider.getBalance(deployer.address);
    console.log("Account balance:", balance.toString());

    // Deploy ZODAVerifier first
    console.log("\n=== Deploying ZODAVerifier ===");
    const ZODAVerifier = await ethers.getContractFactory("ZODAVerifier");
    const zodaVerifier = await ZODAVerifier.deploy();
    await zodaVerifier.waitForDeployment();
    const zodaVerifierAddress = await zodaVerifier.getAddress();
    console.log(`ZODAVerifier deployed to: ${zodaVerifierAddress}`);
    
    // Deploy PCCVerifierBridge
    console.log("\n=== Deploying PCCVerifierBridge ===");
    const PCCVerifierBridge = await ethers.getContractFactory("PCCVerifierBridge");
    const pccVerifierBridge = await PCCVerifierBridge.deploy();
    await pccVerifierBridge.waitForDeployment();
    const pccVerifierAddress = await pccVerifierBridge.getAddress();
    console.log(`PCCVerifierBridge deployed to: ${pccVerifierAddress}`);
    
    // Connect ZODA verifier to PCC bridge
    console.log("\n=== Connecting ZODA Verifier ===");
    const setZodaTx = await pccVerifierBridge.setZODAVerifier(zodaVerifierAddress);
    await setZodaTx.wait();
    console.log("ZODA verifier connected successfully");
    
    // Set verification mode if specified
    const verificationMode = process.env.VERIFICATION_MODE || 'permissive';
    let modeValue = 0; // PERMISSIVE
    if (verificationMode === 'oracle') modeValue = 1;
    else if (verificationMode === 'proof') modeValue = 2;
    else if (verificationMode === 'hybrid') modeValue = 3;
    
    console.log(`Setting verification mode to: ${verificationMode} (${modeValue})`);
    const setModeTx = await pccVerifierBridge.setVerificationMode(modeValue);
    await setModeTx.wait();
    console.log("Verification mode set successfully");

    // Deploy VerifiedAtomicExecutor
    console.log("\n2. Deploying VerifiedAtomicExecutor...");
    const VerifiedAtomicExecutor = await ethers.getContractFactory("VerifiedAtomicExecutor");
    const atomicExecutor = await VerifiedAtomicExecutor.deploy();
    await atomicExecutor.waitForDeployment();
    console.log("VerifiedAtomicExecutor deployed to:", await atomicExecutor.getAddress());

    // Set the PCC verifier in the atomic executor
    console.log("\n3. Connecting PCC Verifier to Atomic Executor...");
    await atomicExecutor.setPCCVerifier(pccVerifierAddress);
    console.log("PCC Verifier address set in atomic executor");

    // Verify the connection
    const connectedVerifier = await atomicExecutor.pccVerifier();
    console.log("Connected PCC Verifier:", connectedVerifier);

    // Save deployment info
    const deploymentInfo = {
        network: await ethers.provider.getNetwork(),
        timestamp: new Date().toISOString(),
        deployer: deployer.address,
        contracts: {
            ZODAVerifier: {
                address: zodaVerifierAddress
            },
            PCCVerifierBridge: {
                address: pccVerifierAddress,
                verificationMode: verificationMode,
                zodaVerifier: zodaVerifierAddress
            },
            VerifiedAtomicExecutor: {
                address: await atomicExecutor.getAddress(),
                pccVerifier: connectedVerifier
            }
        },
        transactionHashes: {
            zodaVerifier: zodaVerifier.deploymentTransaction()?.hash || 'N/A',
            pccVerifierBridge: pccVerifierBridge.deploymentTransaction()?.hash || 'N/A',
            verifiedAtomicExecutor: atomicExecutor.deploymentTransaction()?.hash || 'N/A'
        }
    };

    const deploymentPath = path.join(__dirname, "..", "deployments", "latest.json");
    const deploymentDir = path.dirname(deploymentPath);
    if (!fs.existsSync(deploymentDir)) {
        fs.mkdirSync(deploymentDir, { recursive: true });
    }
    
    fs.writeFileSync(deploymentPath, JSON.stringify(deploymentInfo, null, 2));
    console.log("\n4. Deployment info saved to:", deploymentPath);

    // Generate Rust configuration
    const atomicExecutorAddr = await atomicExecutor.getAddress();
    
    const rustConfig = `
// Auto-generated deployment configuration
// Generated at: ${deploymentInfo.timestamp}

use ethers::types::Address;
use std::str::FromStr;

pub const VERIFIED_ATOMIC_EXECUTOR_ADDRESS: &str = "${atomicExecutorAddr}";
pub const PCC_VERIFIER_BRIDGE_ADDRESS: &str = "${pccVerifierAddress}";
pub const ZODA_VERIFIER_ADDRESS: &str = "${zodaVerifierAddress}";

pub fn get_atomic_executor_address() -> Address {
    Address::from_str(VERIFIED_ATOMIC_EXECUTOR_ADDRESS).unwrap()
}

pub fn get_pcc_verifier_address() -> Address {
    Address::from_str(PCC_VERIFIER_BRIDGE_ADDRESS).unwrap()
}
`;

    const rustConfigPath = path.join(__dirname, "..", "..", "stateless-vm", "src", "config", "deployment.rs");
    const rustConfigDir = path.dirname(rustConfigPath);
    if (!fs.existsSync(rustConfigDir)) {
        fs.mkdirSync(rustConfigDir, { recursive: true });
    }
    
    fs.writeFileSync(rustConfigPath, rustConfig);
    console.log("5. Rust configuration saved to:", rustConfigPath);

    console.log("\n🎉 Deployment complete!");
    console.log(`
=== Deployment Summary ===
ZODAVerifier: ${zodaVerifierAddress}
PCCVerifierBridge: ${pccVerifierAddress}
VerifiedAtomicExecutor: ${await atomicExecutor.getAddress()}
Network: ${deploymentInfo.network.name} (Chain ID: ${deploymentInfo.network.chainId})

Next steps:
1. Update your StatelessVM configuration to use these addresses
2. Set up a trusted oracle for PCC verification (if using ORACLE mode)
3. Test atomic execution with PCC proof verification
    `);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("Deployment failed:", error);
        process.exit(1);
    });
