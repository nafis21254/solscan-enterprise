// SPDX-License-Identifier: MIT
// Test fixture: This contract is SAFE — SolScan should report 0 findings.
pragma solidity ^0.8.20;

/// @title SafeVault — Correctly implements CEI pattern with 0.8.0+ overflow checks
contract SafeVault {

    mapping(address => uint256) public balances;
    bool private locked;

    modifier noReentrancy() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable {
        // Safe: Solidity >= 0.8.0 has built-in overflow checks
        balances[msg.sender] += msg.value;
    }

    function withdraw() external noReentrancy {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // CORRECT: State updated BEFORE external call (CEI pattern)
        balances[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function getBalance(address _user) external view returns (uint256) {
        return balances[_user];
    }
}
