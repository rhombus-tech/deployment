// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FractalTaskRegistry
 * @notice On-chain task registry for fractal proving network
 * @dev Allows users to submit tasks and track their completion
 */
contract FractalTaskRegistry {
    struct Task {
        bytes32 taskId;
        address requester;
        bytes taskData; // Serialized ZODAProofTask
        uint256 reward;
        uint256 deadline;
        uint256 createdAt;
        address assignedProver;
        TaskStatus status;
    }
    
    enum TaskStatus {
        Pending,
        Claimed,
        Completed,
        Verified,
        Expired
    }
    
    // Task storage
    mapping(bytes32 => Task) public tasks;
    bytes32[] public taskList;
    
    // Task indexing
    mapping(address => bytes32[]) public requesterTasks;
    mapping(address => bytes32[]) public proverTasks;
    mapping(TaskStatus => bytes32[]) public tasksByStatus;
    
    // Configuration
    uint256 public minimumReward = 100;
    uint256 public maximumDeadline = 1 hours;
    uint256 public taskFee = 0.001 ether; // Fee to submit task
    
    // Treasury
    address public treasury;
    
    // Events
    event TaskSubmitted(bytes32 indexed taskId, address indexed requester, uint256 reward);
    event TaskClaimed(bytes32 indexed taskId, address indexed prover);
    event TaskCompleted(bytes32 indexed taskId, address indexed prover);
    event TaskVerified(bytes32 indexed taskId);
    event TaskExpired(bytes32 indexed taskId);
    
    constructor(address _treasury) {
        treasury = _treasury;
    }
    
    /**
     * @notice Submit a new proving task
     * @param taskData Serialized task data
     * @param deadline Task deadline (timestamp)
     */
    function submitTask(
        bytes calldata taskData,
        uint256 deadline
    ) external payable returns (bytes32) {
        require(msg.value >= minimumReward + taskFee, "Insufficient payment");
        require(deadline <= block.timestamp + maximumDeadline, "Deadline too far");
        require(deadline > block.timestamp, "Deadline in past");
        
        // Generate task ID
        bytes32 taskId = keccak256(abi.encodePacked(
            msg.sender,
            taskData,
            block.timestamp,
            block.number
        ));
        
        require(tasks[taskId].requester == address(0), "Task ID collision");
        
        uint256 reward = msg.value - taskFee;
        
        // Create task
        Task memory newTask = Task({
            taskId: taskId,
            requester: msg.sender,
            taskData: taskData,
            reward: reward,
            deadline: deadline,
            createdAt: block.timestamp,
            assignedProver: address(0),
            status: TaskStatus.Pending
        });
        
        tasks[taskId] = newTask;
        taskList.push(taskId);
        requesterTasks[msg.sender].push(taskId);
        tasksByStatus[TaskStatus.Pending].push(taskId);
        
        // Send fee to treasury
        (bool success, ) = treasury.call{value: taskFee}("");
        require(success, "Fee transfer failed");
        
        emit TaskSubmitted(taskId, msg.sender, reward);
        
        return taskId;
    }
    
    /**
     * @notice Claim a task for proving
     * @param taskId Task identifier
     */
    function claimTask(bytes32 taskId) external {
        Task storage task = tasks[taskId];
        require(task.status == TaskStatus.Pending, "Task not available");
        require(block.timestamp < task.deadline, "Task expired");
        
        task.status = TaskStatus.Claimed;
        task.assignedProver = msg.sender;
        proverTasks[msg.sender].push(taskId);
        
        // Update status index
        _removeFromStatusArray(TaskStatus.Pending, taskId);
        tasksByStatus[TaskStatus.Claimed].push(taskId);
        
        emit TaskClaimed(taskId, msg.sender);
    }
    
    /**
     * @notice Mark task as completed
     * @param taskId Task identifier
     */
    function completeTask(bytes32 taskId) external {
        Task storage task = tasks[taskId];
        require(task.status == TaskStatus.Claimed, "Task not claimed");
        require(task.assignedProver == msg.sender, "Not assigned prover");
        require(block.timestamp < task.deadline, "Task expired");
        
        task.status = TaskStatus.Completed;
        
        // Update status index
        _removeFromStatusArray(TaskStatus.Claimed, taskId);
        tasksByStatus[TaskStatus.Completed].push(taskId);
        
        emit TaskCompleted(taskId, msg.sender);
    }
    
    /**
     * @notice Verify and pay for completed task
     * @param taskId Task identifier
     */
    function verifyAndPay(bytes32 taskId) external {
        Task storage task = tasks[taskId];
        require(task.status == TaskStatus.Completed, "Task not completed");
        
        task.status = TaskStatus.Verified;
        
        // Update status index
        _removeFromStatusArray(TaskStatus.Completed, taskId);
        tasksByStatus[TaskStatus.Verified].push(taskId);
        
        // Pay prover
        uint256 reward = task.reward;
        task.reward = 0; // Prevent re-entrancy
        
        (bool success, ) = task.assignedProver.call{value: reward}("");
        require(success, "Payment failed");
        
        emit TaskVerified(taskId);
    }
    
    /**
     * @notice Expire tasks past deadline
     * @param taskIds Array of task IDs to check
     */
    function expireTasks(bytes32[] calldata taskIds) external {
        for (uint256 i = 0; i < taskIds.length; i++) {
            bytes32 taskId = taskIds[i];
            Task storage task = tasks[taskId];
            
            if (block.timestamp >= task.deadline && 
                task.status != TaskStatus.Verified &&
                task.status != TaskStatus.Expired) {
                
                task.status = TaskStatus.Expired;
                
                // Refund requester
                if (task.reward > 0) {
                    uint256 refund = task.reward;
                    task.reward = 0;
                    (bool success, ) = task.requester.call{value: refund}("");
                    require(success, "Refund failed");
                }
                
                emit TaskExpired(taskId);
            }
        }
    }
    
    /**
     * @notice Get pending tasks
     */
    function getPendingTasks() external view returns (bytes32[] memory) {
        return tasksByStatus[TaskStatus.Pending];
    }
    
    /**
     * @notice Get task details
     */
    function getTask(bytes32 taskId) external view returns (Task memory) {
        return tasks[taskId];
    }
    
    /**
     * @notice Get tasks by requester
     */
    function getRequesterTasks(address requester) external view returns (bytes32[] memory) {
        return requesterTasks[requester];
    }
    
    /**
     * @notice Get tasks by prover
     */
    function getProverTasks(address prover) external view returns (bytes32[] memory) {
        return proverTasks[prover];
    }
    
    /**
     * @notice Get total task count
     */
    function getTotalTasks() external view returns (uint256) {
        return taskList.length;
    }
    
    // Helper function to remove from status array
    function _removeFromStatusArray(TaskStatus status, bytes32 taskId) private {
        bytes32[] storage arr = tasksByStatus[status];
        for (uint256 i = 0; i < arr.length; i++) {
            if (arr[i] == taskId) {
                arr[i] = arr[arr.length - 1];
                arr.pop();
                break;
            }
        }
    }
}
