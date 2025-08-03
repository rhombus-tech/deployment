const { ethers } = require("hardhat");

async function main() {
    console.log("🚀 Deploying VerifiedAtomicExecutor...");

    // Get the deployer account
    const [deployer] = await ethers.getSigners();
    console.log("Deploying with account:", deployer.address);
    console.log("Account balance:", (await ethers.provider.getBalance(deployer.address)).toString());

    // Deploy VerifiedAtomicExecutor
    const VerifiedAtomicExecutor = await ethers.getContractFactory("VerifiedAtomicExecutor");
    const atomicExecutor = await VerifiedAtomicExecutor.deploy();
    
    await atomicExecutor.waitForDeployment();
    
    console.log("✅ VerifiedAtomicExecutor deployed to:", await atomicExecutor.getAddress());
    
    // Save deployment info
    const contractAddress = await atomicExecutor.getAddress();
    const deploymentInfo = {
        contractAddress: contractAddress,
        deployer: deployer.address,
        network: await ethers.provider.getNetwork(),
        blockNumber: await ethers.provider.getBlockNumber(),
        timestamp: Date.now(),
        gasUsed: (await atomicExecutor.deploymentTransaction().wait()).gasUsed.toString()
    };
    
    console.log("📊 Deployment Info:", deploymentInfo);
    
    // Verify contract interaction by calling a view function
    try {
        const owner = await atomicExecutor.owner();
        console.log("✅ Contract owner verified:", owner);
        console.log("🎯 Contract is ready for HFT integration!");
    } catch (error) {
        console.error("❌ Error verifying contract:", error.message);
    }
    
    return atomicExecutor;
}

// Export for testing
if (require.main === module) {
    main()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error("❌ Deployment failed:", error);
            process.exit(1);
        });
}

module.exports = { main };
