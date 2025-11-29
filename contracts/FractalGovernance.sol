// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

interface IFractalStaking {
    function voteWeight(address staker) external view returns (uint256);
    function stakes(address staker) external view returns (
        uint256 amount,
        uint256 timestamp,
        uint256 lockPeriod,
        uint256 lastClaimTime,
        uint256 accumulatedRewards,
        bool active
    );
}

/**
 * @title FractalGovernance
 * @notice DAO governance for the Fractal Proving Network
 * @dev Stake-weighted voting on protocol parameters and upgrades
 */
contract FractalGovernance is ReentrancyGuard, AccessControl {
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    
    IFractalStaking public stakingContract;
    
    // Proposal types
    enum ProposalType {
        ParameterChange,    // Change protocol parameters
        Upgrade,            // Upgrade contracts
        Treasury,           // Treasury spending
        Integration,        // Add new integrations
        Emergency           // Emergency actions
    }
    
    // Proposal states
    enum ProposalState {
        Pending,      // Discussion period
        Active,       // Voting in progress
        Succeeded,    // Passed and ready for execution
        Executed,     // Executed
        Defeated,     // Failed to reach quorum or majority
        Cancelled     // Cancelled by proposer or admin
    }
    
    struct Proposal {
        uint256 id;
        address proposer;
        ProposalType proposalType;
        string title;
        string description;
        bytes executionData;
        address targetContract;
        
        uint256 creationTime;
        uint256 votingStartTime;
        uint256 votingEndTime;
        
        uint256 forVotes;
        uint256 againstVotes;
        uint256 abstainVotes;
        
        ProposalState state;
        
        uint256 quorumRequired;
        uint256 approvalThreshold;
    }
    
    struct Vote {
        bool hasVoted;
        bool support;      // true = for, false = against
        bool abstain;
        uint256 weight;
    }
    
    // Governance parameters
    uint256 public constant PROPOSAL_THRESHOLD = 10_000 * 10**18; // 10,000 FRAC to propose
    uint256 public constant DISCUSSION_PERIOD = 7 days;
    uint256 public constant VOTING_PERIOD = 7 days;
    uint256 public constant EXECUTION_DELAY = 2 days;
    
    // Quorum requirements (basis points of total staked)
    uint256 public constant DEFAULT_QUORUM = 2000;      // 20%
    uint256 public constant EMERGENCY_QUORUM = 5000;    // 50%
    
    // Approval thresholds (basis points of votes cast)
    uint256 public constant DEFAULT_THRESHOLD = 5000;    // 50%
    uint256 public constant PARAMETER_THRESHOLD = 6000;  // 60%
    uint256 public constant UPGRADE_THRESHOLD = 7500;    // 75%
    uint256 public constant EMERGENCY_THRESHOLD = 8000;  // 80%
    
    // Storage
    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => Vote)) public votes;
    uint256 public proposalCount;
    
    // Events
    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed proposer,
        ProposalType proposalType,
        string title
    );
    event VoteCast(
        uint256 indexed proposalId,
        address indexed voter,
        bool support,
        uint256 weight
    );
    event ProposalExecuted(uint256 indexed proposalId);
    event ProposalCancelled(uint256 indexed proposalId);
    event ProposalStateChanged(uint256 indexed proposalId, ProposalState newState);
    
    constructor(address _stakingContract) {
        require(_stakingContract != address(0), "Invalid staking contract");
        stakingContract = IFractalStaking(_stakingContract);
        
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(EXECUTOR_ROLE, msg.sender);
    }
    
    /**
     * @notice Create a new proposal
     */
    function propose(
        ProposalType proposalType,
        string calldata title,
        string calldata description,
        address targetContract,
        bytes calldata executionData
    ) external returns (uint256) {
        // Check proposer has enough vote weight
        uint256 proposerWeight = stakingContract.voteWeight(msg.sender);
        require(proposerWeight >= PROPOSAL_THRESHOLD, "Insufficient stake to propose");
        
        // Determine quorum and threshold based on type
        (uint256 quorum, uint256 threshold) = getRequirements(proposalType);
        
        uint256 proposalId = ++proposalCount;
        
        Proposal storage newProposal = proposals[proposalId];
        newProposal.id = proposalId;
        newProposal.proposer = msg.sender;
        newProposal.proposalType = proposalType;
        newProposal.title = title;
        newProposal.description = description;
        newProposal.executionData = executionData;
        newProposal.targetContract = targetContract;
        newProposal.creationTime = block.timestamp;
        newProposal.votingStartTime = block.timestamp + DISCUSSION_PERIOD;
        newProposal.votingEndTime = block.timestamp + DISCUSSION_PERIOD + VOTING_PERIOD;
        newProposal.state = ProposalState.Pending;
        newProposal.quorumRequired = quorum;
        newProposal.approvalThreshold = threshold;
        
        emit ProposalCreated(proposalId, msg.sender, proposalType, title);
        
        return proposalId;
    }
    
    /**
     * @notice Cast a vote on a proposal
     */
    function castVote(
        uint256 proposalId,
        bool support,
        bool abstain
    ) external nonReentrant {
        Proposal storage proposal = proposals[proposalId];
        require(proposal.id != 0, "Proposal does not exist");
        require(getState(proposalId) == ProposalState.Active, "Voting not active");
        
        Vote storage vote = votes[proposalId][msg.sender];
        require(!vote.hasVoted, "Already voted");
        
        // Get voter's weight from staking contract
        uint256 weight = stakingContract.voteWeight(msg.sender);
        require(weight > 0, "No voting power");
        
        // Record vote
        vote.hasVoted = true;
        vote.support = support;
        vote.abstain = abstain;
        vote.weight = weight;
        
        // Update proposal tallies
        if (abstain) {
            proposal.abstainVotes += weight;
        } else if (support) {
            proposal.forVotes += weight;
        } else {
            proposal.againstVotes += weight;
        }
        
        emit VoteCast(proposalId, msg.sender, support, weight);
    }
    
    /**
     * @notice Execute a passed proposal
     */
    function execute(uint256 proposalId) external nonReentrant onlyRole(EXECUTOR_ROLE) {
        Proposal storage proposal = proposals[proposalId];
        require(proposal.id != 0, "Proposal does not exist");
        require(getState(proposalId) == ProposalState.Succeeded, "Proposal not ready for execution");
        require(
            block.timestamp >= proposal.votingEndTime + EXECUTION_DELAY,
            "Execution delay not passed"
        );
        
        proposal.state = ProposalState.Executed;
        
        // Execute the proposal
        if (proposal.executionData.length > 0 && proposal.targetContract != address(0)) {
            (bool success, ) = proposal.targetContract.call(proposal.executionData);
            require(success, "Execution failed");
        }
        
        emit ProposalExecuted(proposalId);
        emit ProposalStateChanged(proposalId, ProposalState.Executed);
    }
    
    /**
     * @notice Cancel a proposal
     */
    function cancel(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        require(proposal.id != 0, "Proposal does not exist");
        require(
            msg.sender == proposal.proposer || hasRole(DEFAULT_ADMIN_ROLE, msg.sender),
            "Only proposer or admin can cancel"
        );
        require(
            proposal.state == ProposalState.Pending || proposal.state == ProposalState.Active,
            "Cannot cancel executed proposal"
        );
        
        proposal.state = ProposalState.Cancelled;
        
        emit ProposalCancelled(proposalId);
        emit ProposalStateChanged(proposalId, ProposalState.Cancelled);
    }
    
    /**
     * @notice Get current state of a proposal
     */
    function getState(uint256 proposalId) public view returns (ProposalState) {
        Proposal storage proposal = proposals[proposalId];
        require(proposal.id != 0, "Proposal does not exist");
        
        // Return stored state if it's a terminal state
        if (
            proposal.state == ProposalState.Executed ||
            proposal.state == ProposalState.Cancelled
        ) {
            return proposal.state;
        }
        
        // Check if voting period started
        if (block.timestamp < proposal.votingStartTime) {
            return ProposalState.Pending;
        }
        
        // Check if voting is active
        if (block.timestamp < proposal.votingEndTime) {
            return ProposalState.Active;
        }
        
        // Voting ended, check results
        uint256 totalVotes = proposal.forVotes + proposal.againstVotes + proposal.abstainVotes;
        uint256 totalStaked = getTotalStaked();
        
        // Check quorum (% of total staked)
        uint256 quorumNeeded = (totalStaked * proposal.quorumRequired) / 10000;
        if (totalVotes < quorumNeeded) {
            return ProposalState.Defeated;
        }
        
        // Check approval threshold (% of votes cast, excluding abstentions)
        uint256 votesForDecision = proposal.forVotes + proposal.againstVotes;
        if (votesForDecision == 0) {
            return ProposalState.Defeated;
        }
        
        uint256 approvalNeeded = (votesForDecision * proposal.approvalThreshold) / 10000;
        if (proposal.forVotes >= approvalNeeded) {
            return ProposalState.Succeeded;
        }
        
        return ProposalState.Defeated;
    }
    
    /**
     * @notice Get quorum and threshold requirements for proposal type
     */
    function getRequirements(ProposalType proposalType) public pure returns (
        uint256 quorum,
        uint256 threshold
    ) {
        if (proposalType == ProposalType.Emergency) {
            return (EMERGENCY_QUORUM, EMERGENCY_THRESHOLD);
        } else if (proposalType == ProposalType.Upgrade) {
            return (DEFAULT_QUORUM, UPGRADE_THRESHOLD);
        } else if (proposalType == ProposalType.ParameterChange) {
            return (DEFAULT_QUORUM, PARAMETER_THRESHOLD);
        } else {
            return (DEFAULT_QUORUM, DEFAULT_THRESHOLD);
        }
    }
    
    /**
     * @notice Get total staked amount from staking contract
     */
    function getTotalStaked() public view returns (uint256) {
        // This would need to be implemented by FractalStaking
        // For now, return a placeholder
        return 1_000_000 * 10**18; // 1M FRAC
    }
    
    /**
     * @notice Get detailed proposal information
     */
    function getProposal(uint256 proposalId) external view returns (
        address proposer,
        ProposalType proposalType,
        string memory title,
        string memory description,
        uint256 creationTime,
        uint256 votingStartTime,
        uint256 votingEndTime,
        uint256 forVotes,
        uint256 againstVotes,
        uint256 abstainVotes,
        ProposalState state,
        uint256 quorumRequired,
        uint256 approvalThreshold
    ) {
        Proposal storage proposal = proposals[proposalId];
        require(proposal.id != 0, "Proposal does not exist");
        
        return (
            proposal.proposer,
            proposal.proposalType,
            proposal.title,
            proposal.description,
            proposal.creationTime,
            proposal.votingStartTime,
            proposal.votingEndTime,
            proposal.forVotes,
            proposal.againstVotes,
            proposal.abstainVotes,
            getState(proposalId),
            proposal.quorumRequired,
            proposal.approvalThreshold
        );
    }
    
    /**
     * @notice Check if an address has voted on a proposal
     */
    function hasVoted(uint256 proposalId, address voter) external view returns (bool) {
        return votes[proposalId][voter].hasVoted;
    }
    
    /**
     * @notice Get vote details for an address on a proposal
     */
    function getVote(uint256 proposalId, address voter) external view returns (
        bool hasVoted_,
        bool support,
        bool abstain,
        uint256 weight
    ) {
        Vote storage vote = votes[proposalId][voter];
        return (
            vote.hasVoted,
            vote.support,
            vote.abstain,
            vote.weight
        );
    }
    
    /**
     * @notice Get all active proposals
     */
    function getActiveProposals() external view returns (uint256[] memory) {
        uint256[] memory activeIds = new uint256[](proposalCount);
        uint256 count = 0;
        
        for (uint256 i = 1; i <= proposalCount; i++) {
            ProposalState state = getState(i);
            if (state == ProposalState.Pending || state == ProposalState.Active) {
                activeIds[count] = i;
                count++;
            }
        }
        
        // Resize array to actual count
        uint256[] memory result = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            result[i] = activeIds[i];
        }
        
        return result;
    }
    
    /**
     * @notice Get voting power for an address
     */
    function getVotingPower(address voter) external view returns (uint256) {
        return stakingContract.voteWeight(voter);
    }
}
