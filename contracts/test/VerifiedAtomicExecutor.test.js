const { expect } = require("chai");
const { ethers } = require("hardhat");

// Test contract source code for compilation
const testContractSource = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract TestContract {
    uint256 public value;
    bool public shouldFail;
    
    function setValue(uint256 _value) external {
        value = _value;
    }
    
    function increment() external {
        value += 1;
    }
    
    function failTransaction() external {
        require(!shouldFail, "Transaction failed as requested");
    }
    
    function setShouldFail(bool _shouldFail) external {
        shouldFail = _shouldFail;
    }
    
    function getValue() external view returns (uint256) {
        return value;
    }
    
    // Function that accepts ether
    function deposit() external payable {
        // Just accept the ether
    }
    
    // Function to get contract balance
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
    
    // Receive function to accept ether
    receive() external payable {}
}
`;

// Mock PCC Verifier for testing
const mockPCCVerifierSource = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract MockPCCVerifier {
    mapping(bytes32 => bool) public verificationResults;
    bool public alwaysPass = true;
    
    function setVerificationResult(bytes32 proofHash, bool result) external {
        verificationResults[proofHash] = result;
    }
    
    function setAlwaysPass(bool _alwaysPass) external {
        alwaysPass = _alwaysPass;
    }
    
    function verifyProof(bytes32 proofHash, bytes calldata) external view returns (bool) {
        if (alwaysPass) return proofHash != bytes32(0);
        return verificationResults[proofHash];
    }
    
    function verifyProofWithContext(
        bytes32 proofHash,
        bytes calldata,
        bytes calldata
    ) external view returns (bool) {
        if (alwaysPass) return proofHash != bytes32(0);
        return verificationResults[proofHash];
    }
    
    function getVerificationConfig() external view returns (bool enabled, bool strictMode) {
        return (true, false);
    }
}
`;

describe("VerifiedAtomicExecutor", function () {
  let atomicExecutor;
  let owner;
  let addr1;
  let addr2;
  let testContract;

  beforeEach(async function () {
    [owner, addr1, addr2] = await ethers.getSigners();

    // Deploy test contract for operations
    const TestContract = await ethers.getContractFactory("TestContract");
    testContract = await TestContract.deploy();
    await testContract.waitForDeployment();

    // Deploy VerifiedAtomicExecutor
    const VerifiedAtomicExecutor = await ethers.getContractFactory("VerifiedAtomicExecutor");
    atomicExecutor = await VerifiedAtomicExecutor.deploy();
    await atomicExecutor.waitForDeployment();
  });

  describe("Deployment", function () {
    it("Should set the right owner", async function () {
      expect(await atomicExecutor.owner()).to.equal(owner.address);
    });

    it("Should have no PCC verifier initially", async function () {
      expect(await atomicExecutor.pccVerifier()).to.equal(ethers.ZeroAddress);
    });
  });

  describe("Atomic Execution Without Proof", function () {
    it("Should execute single operation atomically", async function () {
      const operations = [{
        target: await testContract.getAddress(),
        callData: testContract.interface.encodeFunctionData("setValue", [42]),
        value: 0
      }];

      const tx = await atomicExecutor.executeWithoutProof(operations);
      const receipt = await tx.wait();

      expect(receipt.status).to.equal(1);
      expect(await testContract.value()).to.equal(42);
    });

    it("Should execute multiple operations atomically", async function () {
      const operations = [
        {
          target: await testContract.getAddress(),
          callData: testContract.interface.encodeFunctionData("setValue", [100]),
          value: 0
        },
        {
          target: await testContract.getAddress(),
          callData: testContract.interface.encodeFunctionData("increment"),
          value: 0
        }
      ];

      await atomicExecutor.executeWithoutProof(operations);

      expect(await testContract.value()).to.equal(101);
    });

    it("Should revert all operations if one fails", async function () {
      // Set the test contract to fail
      await testContract.setShouldFail(true);
      
      const operations = [
        {
          target: await testContract.getAddress(),
          callData: testContract.interface.encodeFunctionData("setValue", [200]),
          value: 0
        },
        {
          target: await testContract.getAddress(),
          callData: testContract.interface.encodeFunctionData("failTransaction"),
          value: 0
        }
      ];

      await expect(
        atomicExecutor.executeWithoutProof(operations)
      ).to.be.reverted;

      // Value should remain unchanged
      expect(await testContract.value()).to.equal(0);
    });

    it("Should emit AtomicExecutionSuccess event", async function () {
      const operations = [{
        target: await testContract.getAddress(),
        callData: testContract.interface.encodeFunctionData("setValue", [42]),
        value: 0
      }];

      await expect(atomicExecutor.executeWithoutProof(operations))
        .to.emit(atomicExecutor, "AtomicExecutionSuccess");
    });
  });

  describe("Atomic Execution With Proof", function () {
    it("Should execute with valid proof", async function () {
      const proof = {
        pccProofHash: ethers.keccak256(ethers.toUtf8Bytes("valid_pcc_proof")),
        pcdProofHash: ethers.keccak256(ethers.toUtf8Bytes("valid_pcd_proof")),
        stateRoot: ethers.ZeroHash,
        gasLimit: 5000000
      };

      const operations = [{
        target: await testContract.getAddress(),
        callData: testContract.interface.encodeFunctionData("setValue", [42]),
        value: 0
      }];

      const tx = await atomicExecutor.executeWithProof(proof, operations);
      const receipt = await tx.wait();

      expect(receipt.status).to.equal(1);
      expect(await testContract.value()).to.equal(42);
    });

    it("Should execute same proof multiple times (timestamp makes hash unique)", async function () {
      const proof = {
        pccProofHash: ethers.keccak256(ethers.toUtf8Bytes("unique_proof")),
        pcdProofHash: ethers.keccak256(ethers.toUtf8Bytes("unique_pcd_proof")),
        stateRoot: ethers.ZeroHash,
        gasLimit: 5000000
      };

      const operations = [{
        target: await testContract.getAddress(),
        callData: testContract.interface.encodeFunctionData("setValue", [42]),
        value: 0
      }];

      // First execution should succeed
      await atomicExecutor.executeWithProof(proof, operations);
      expect(await testContract.value()).to.equal(42);

      // Second execution should also succeed because timestamp changes hash
      // (This demonstrates the current behavior - we could modify if needed)
      await atomicExecutor.executeWithProof(proof, operations);
      expect(await testContract.value()).to.equal(42);
    });
  });

  describe("Owner Functions", function () {
    it("Should allow owner to set PCC verifier", async function () {
      await atomicExecutor.setPCCVerifier(addr1.address);
      expect(await atomicExecutor.pccVerifier()).to.equal(addr1.address);
    });

    it("Should not allow non-owner to set PCC verifier", async function () {
      await expect(
        atomicExecutor.connect(addr1).setPCCVerifier(addr2.address)
      ).to.be.revertedWith("Ownable: caller is not the owner");
    });

    it("Should allow owner to emergency withdraw", async function () {
      // Send some ETH to the contract
      await owner.sendTransaction({
        to: await atomicExecutor.getAddress(),
        value: ethers.parseEther("1.0")
      });

      const initialBalance = await ethers.provider.getBalance(owner.address);
      
      await atomicExecutor.emergencyWithdraw();
      
      const finalBalance = await ethers.provider.getBalance(owner.address);
      expect(finalBalance).to.be.gt(initialBalance);
    });
  });

  // TODO: Add PCC Verifier Integration tests
  // These require deploying the PCCVerifierBridge contract first
});

// Test contract for atomic operations
const TestContractSource = `
pragma solidity ^0.8.19;

contract TestContract {
    uint256 public value;
    
    function setValue(uint256 _value) external {
        value = _value;
    }
    
    function increment() external {
        value++;
    }
    
    function failTransaction() external pure {
        revert("Test failure");
    }
}
`;

// We'll need to create this test contract separately
