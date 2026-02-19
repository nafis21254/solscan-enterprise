// SPDX-License-Identifier: MIT
// Test fixture: INTENTIONALLY VULNERABLE — do not deploy!
pragma solidity ^0.7.6;

/// @title VulnerableVault — Reentrancy + Integer Overflow test target
/// @notice This contract contains BOTH vulnerability classes that SolScan detects.
contract VulnerableVault {

    mapping(address => uint256) public balances;

    // ------------------------------------------------------------------
    // SOLSCAN-001: Reentrancy — external call BEFORE state update
    // ------------------------------------------------------------------
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // BUG: External call before state update (CEI violation)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // This line should come BEFORE the call above
        balances[msg.sender] = 0;
    }

    // ------------------------------------------------------------------
    // SOLSCAN-002: Integer Overflow — unchecked arithmetic in < 0.8.0
    // ------------------------------------------------------------------
    function deposit() external payable {
        // BUG: In Solidity < 0.8.0, this can overflow silently
        balances[msg.sender] += msg.value;
    }

    function transfer(address _to, uint256 _amount) external {
        require(balances[msg.sender] >= _amount, "Insufficient");

        // BUG: Both of these can overflow/underflow
        balances[msg.sender] -= _amount;
        balances[_to] += _amount;
    }

    // Safe function — should NOT be flagged
    function getBalance(address _user) external view returns (uint256) {
        return balances[_user];
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
