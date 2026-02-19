"""
SOLSCAN-001: Reentrancy Detector
=================================

Detects violations of the **Check-Effects-Interactions** (CEI) pattern.

Background
----------
Reentrancy is the #1 smart-contract vulnerability class (see: The DAO hack,
2016). It occurs when a contract makes an external call *before* updating its
own state. The callee can re-enter the calling function and exploit the
stale state.

    // VULNERABLE — external call BEFORE state update
    function withdraw() external {
        uint amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");   // ← interaction
        require(ok);
        balances[msg.sender] = 0;                          // ← effect (too late!)
    }

Detection Algorithm (SlithIR-based)
-----------------------------------
For every non-view/pure function in a contract:
  1. Walk the function's control-flow graph (CFG) node by node.
  2. Track two boolean flags:
       • `seen_external_call`  — set when we encounter HighLevelCall /
          LowLevelCall / Send / Transfer
       • `state_write_after`   — set when we see a state variable write
          AFTER `seen_external_call` is already True
  3. If both flags are True at the end of the walk, this function violates
     CEI and we emit a Finding.

Limitations
-----------
- Cross-function reentrancy (function A calls external, function B writes
  state) requires inter-procedural analysis and is tracked as SOLSCAN-003.
- Read-only reentrancy (EIP-3156 flash loans) is a separate detector.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from src.detectors import BaseDetector, Confidence, Finding, Severity

if TYPE_CHECKING:
    from slither.core.declarations import Contract, Function
    from slither.core.cfg.node import Node

logger = logging.getLogger(__name__)


class ReentrancyDetector(BaseDetector):
    """Detects single-function Check-Effects-Interactions violations."""

    DETECTOR_ID = "SOLSCAN-001"
    TITLE = "Reentrancy (CEI Violation)"
    SEVERITY = Severity.CRITICAL
    CONFIDENCE = Confidence.HIGH
    DESCRIPTION = (
        "An external call is made before state variables are updated. "
        "An attacker can re-enter the function and exploit stale state, "
        "potentially draining funds."
    )

    # SWC Registry + relevant references
    _REFERENCES = [
        "https://swcregistry.io/docs/SWC-107",
        "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
    ]

    def detect(self, contract: Contract) -> list[Finding]:
        """
        Scan every non-view function in the contract for CEI violations.

        We walk the CFG nodes in topological order. For each node, we
        inspect the SlithIR operations:
            - HighLevelCall / LowLevelCall / Send / Transfer → external call
            - Assignment / Binary writing a StateVariable → state write

        If a state write appears *after* an external call within the same
        function body, we flag it.
        """
        findings: list[Finding] = []

        for function in contract.functions_declared:
            if self._should_skip(function):
                continue

            result = self._analyze_function(function)
            if result is not None:
                findings.append(result)

        return findings

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _should_skip(func: Function) -> bool:
        """Skip functions that cannot cause reentrancy."""
        # View / pure functions don't modify state
        if func.view or func.pure:
            return True
        # Constructors, fallback, receive have special semantics
        if func.is_constructor or func.is_fallback or func.is_receive:
            return True
        # If the function body is empty, nothing to analyze
        if not func.nodes:
            return True
        return False

    def _analyze_function(self, func: Function) -> Finding | None:
        """
        Walk the CFG and check if an external call precedes a state write.

        Returns a Finding if a violation is detected, else None.
        """
        seen_external_call = False
        external_call_node: Node | None = None
        state_write_node: Node | None = None

        for node in func.nodes:
            for ir_op in node.irs:
                # Phase 1: Look for external calls
                if not seen_external_call and self.is_external_call(ir_op):
                    seen_external_call = True
                    external_call_node = node
                    logger.debug(
                        "  [%s] External call at node %s (line ~%s)",
                        func.full_name,
                        node.node_id,
                        node.source_mapping.get("lines", ["?"])[0]
                        if node.source_mapping
                        else "?",
                    )

                # Phase 2: After an external call, look for state writes
                elif seen_external_call and self.is_state_write(ir_op):
                    state_write_node = node
                    logger.debug(
                        "  [%s] State write AFTER external call at node %s",
                        func.full_name,
                        node.node_id,
                    )
                    break  # One violation per function is enough

            if state_write_node is not None:
                break

        if external_call_node is not None and state_write_node is not None:
            return self._build_finding(func, external_call_node, state_write_node)

        return None

    def _build_finding(
        self,
        func: Function,
        call_node: Node,
        write_node: Node,
    ) -> Finding:
        """Construct a detailed Finding with context about the violation."""
        call_line = (
            call_node.source_mapping.get("lines", [0])[0]
            if call_node.source_mapping
            else 0
        )
        write_line = (
            write_node.source_mapping.get("lines", [0])[0]
            if write_node.source_mapping
            else 0
        )

        description = (
            f"Function `{func.full_name}` in contract `{func.contract_declarer.name}` "
            f"makes an external call (line {call_line}) before updating state "
            f"(line {write_line}). This violates the Check-Effects-Interactions pattern "
            f"and may allow reentrancy attacks."
        )

        recommendation = (
            "Move all state changes BEFORE the external call. "
            "Alternatively, add a reentrancy guard (e.g., OpenZeppelin's "
            "ReentrancyGuard) to the function."
        )

        return self._make_finding(
            func=func,
            description=description,
            recommendation=recommendation,
            references=self._REFERENCES,
        )
