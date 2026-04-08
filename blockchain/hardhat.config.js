/**
 * hardhat.config.js — Vargate blockchain configuration.
 * Supports local Hardhat network (for existing tests) and Sepolia testnet
 * (for Stage 7B Merkle anchoring).
 *
 * Environment variables:
 *   SEPOLIA_RPC_URL        — Alchemy/Infura/public Sepolia RPC endpoint
 *   DEPLOYER_PRIVATE_KEY   — hex private key for the deployer account
 *   ETHERSCAN_API_KEY      — (optional) for contract verification
 */

require("@nomicfoundation/hardhat-toolbox");

// Read from env, with safe fallbacks for local-only usage
const SEPOLIA_RPC_URL      = process.env.SEPOLIA_RPC_URL      || "";
const DEPLOYER_PRIVATE_KEY = process.env.DEPLOYER_PRIVATE_KEY || "";
const ETHERSCAN_API_KEY    = process.env.ETHERSCAN_API_KEY    || "";
const POLYGON_RPC_URL      = process.env.POLYGON_RPC_URL      || "";
const POLYGON_PRIVATE_KEY  = process.env.POLYGON_PRIVATE_KEY  || "";
const POLYGONSCAN_API_KEY  = process.env.POLYGONSCAN_API_KEY  || "";
const ETH_MAINNET_RPC_URL  = process.env.ETH_MAINNET_RPC_URL  || "";
const ETH_MAINNET_PRIVATE_KEY = process.env.ETH_MAINNET_PRIVATE_KEY || "";

const networks = {
  hardhat: {
    chainId: 31337,
    mining: { auto: true, interval: 0 },
  },
};

function ensureKey(key) {
  return key.startsWith("0x") ? key : `0x${key}`;
}

// Sepolia testnet
if (SEPOLIA_RPC_URL && DEPLOYER_PRIVATE_KEY) {
  networks.sepolia = {
    url: SEPOLIA_RPC_URL,
    chainId: 11155111,
    accounts: [ensureKey(DEPLOYER_PRIVATE_KEY)],
    gasMultiplier: 1.2,
  };
}

// Polygon Amoy testnet (chainId 80002)
if (POLYGON_RPC_URL && POLYGON_PRIVATE_KEY) {
  networks.polygon_amoy = {
    url: POLYGON_RPC_URL,
    chainId: 80002,
    accounts: [ensureKey(POLYGON_PRIVATE_KEY)],
    gasMultiplier: 1.2,
  };
}

// Polygon PoS mainnet (chainId 137)
if (POLYGON_RPC_URL && POLYGON_PRIVATE_KEY && !POLYGON_RPC_URL.includes("amoy")) {
  networks.polygon = {
    url: POLYGON_RPC_URL,
    chainId: 137,
    accounts: [ensureKey(POLYGON_PRIVATE_KEY)],
    gasMultiplier: 1.2,
  };
}

// Ethereum mainnet (chainId 1)
if (ETH_MAINNET_RPC_URL && ETH_MAINNET_PRIVATE_KEY) {
  networks.ethereum = {
    url: ETH_MAINNET_RPC_URL,
    chainId: 1,
    accounts: [ensureKey(ETH_MAINNET_PRIVATE_KEY)],
    gasMultiplier: 1.2,
  };
}

module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 },
    },
  },
  networks,
  etherscan: {
    apiKey: {
      sepolia: ETHERSCAN_API_KEY,
      polygon: POLYGONSCAN_API_KEY,
      polygonAmoy: POLYGONSCAN_API_KEY,
      mainnet: ETHERSCAN_API_KEY,
    },
  },
};
