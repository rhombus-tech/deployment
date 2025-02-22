// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TestContract {
    address public owner;
    uint256 public value;
    
    constructor(uint256 _value) {
        owner = msg.sender;
        value = _value;
    }
    
    function setValue(uint256 _value) public {
        require(msg.sender == owner, "Not owner");
        value = _value;
    }
}
