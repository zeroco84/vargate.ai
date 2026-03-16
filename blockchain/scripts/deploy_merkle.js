/**
 * deploy_merkle.js — Deploys MerkleAuditAnchor.sol to Sepolia testnet.
 * Writes deployed address + ABI to /shared/MerkleAuditAnchor.json for the
 * gateway to consume.
 *
 * Usage:
 *   npx hardhat run scripts/deploy_merkle.js --network sepolia
 *
 * Environment:
 *   DEPLOYER_PRIVATE_KEY — hex private key (no 0x prefix ok)
 */

const hre = require("hardhat");
const fs  = require("fs");

async function main() {
    const [deployer] = await hre.ethers.getSigners();
    console.log("Deploying MerkleAuditAnchor with account:", deployer.address);

    const balance = await hre.ethers.provider.getBalance(deployer.address);
    console.log("Account balance:", hre.ethers.formatEther(balance), "ETH");

    if (balance === 0n) {
        console.error("ERROR: Deployer account has zero balance. Fund it with Sepolia ETH first.");
        process.exit(1);
    }

    const MerkleAuditAnchor = await hre.ethers.getContractFactory("MerkleAuditAnchor");
    const contract = await MerkleAuditAnchor.deploy();
    await contract.waitForDeployment();
    const address = await contract.getAddress();

    console.log("MerkleAuditAnchor deployed to:", address);

    // Build combined output: address + ABI
    const artifact = require("../artifacts/contracts/MerkleAuditAnchor.sol/MerkleAuditAnchor.json");
    const output = {
        address: address,
        abi: artifact.abi,
        network: "sepolia",
        deployer: deployer.address,
        deployedAt: new Date().toISOString(),
    };

    // Write to /shared volume (Docker) and also local file
    const sharedPath = "/shared/MerkleAuditAnchor.json";
    const localPath = "./MerkleAuditAnchor-deployed.json";

    try {
        fs.mkdirSync("/shared", { recursive: true });
        fs.writeFileSync(sharedPath, JSON.stringify(output, null, 2));
        console.log(`Contract info written to ${sharedPath}`);
    } catch (err) {
        console.log(`Could not write to ${sharedPath} (not in Docker?), writing locally.`);
    }

    fs.writeFileSync(localPath, JSON.stringify(output, null, 2));
    console.log(`Contract info written to ${localPath}`);

    // Print Etherscan verification command
    console.log("\n── Verify on Etherscan ──");
    console.log(`npx hardhat verify --network sepolia ${address}`);
    console.log(`\nOr visit: https://sepolia.etherscan.io/address/${address}`);
}

main().catch((error) => { console.error(error); process.exit(1); });
