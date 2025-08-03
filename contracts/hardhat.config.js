require("@nomicfoundation/hardhat-toolbox");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.19",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      }
    }
  },
  networks: {
    hardhat: {
      chainId: 1337
    },
    localhost: {
      url: "http://127.0.0.1:8545"
    },
    // Add your network configurations here
    // mainnet: {
    //   url: `https://mainnet.infura.io/v3/${process.env.INFURA_PROJECT_ID}`,
    //   accounts: [process.env.PRIVATE_KEY]
    // }
  }
};
