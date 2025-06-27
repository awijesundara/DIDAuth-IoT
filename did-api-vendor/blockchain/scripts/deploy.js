const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with account:", deployer.address);

  const DIDRegistry = await hre.ethers.getContractFactory("DIDRegistry");
  const contract = await DIDRegistry.deploy();

  await contract.waitForDeployment();

  console.log("✅ DIDRegistry deployed to:", await contract.getAddress());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
