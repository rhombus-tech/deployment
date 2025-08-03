// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title TestContract
 * @dev Simple contract for testing atomic operations
 */
contract TestContract {
    uint256 public value;
    
    event ValueSet(uint256 newValue);
    event ValueIncremented(uint256 newValue);
    
    function setValue(uint256 _value) external {
        value = _value;
        emit ValueSet(_value);
    }
    
    function increment() external {
        value++;
        emit ValueIncremented(value);
    }
    
    function failTransaction() external pure {
        revert("Test failure");
    }
    
    function getValue() external view returns (uint256) {
        return value;
    }
}
