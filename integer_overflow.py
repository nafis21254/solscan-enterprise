"""
SOLSCAN-002: Integer Overflow / Underflow Detector
====================================================

Detects unchecked arithmetic in Solidity contracts compiled with < 0.8.0.

Background
----------
Before Solidity 0.8.0, arithmetic operations silently wrapped on overflow:
    uint8 x = 255;
    x += 1;  // x is now 0, not 256 — no revert!

Solidity 0.8.0+ introduced built-in overflow checks that revert on wrap.
Contracts explicitly using `unchecked { }` blocks in >=0.8.0 are also flagged,
as this deliberately disables the safety net.

Detection Algorithm (SlithIR-based)
-----------------------------------
1. Check the contract's Solidity pragma version.
   - If >= 0.8.0: only flag `Binary` operations inside `unchecked` blocks.
   - If < 0.8.0: flag ALL `Binary` arithmetic operations (+, -, *, **).
2. For each flagged operation, check if the function uses SafeMath or
   equivalent guard patterns (require/assert wrapping the result).
3. Emit findings for unguarded arithmetic.

Why SlithIR?
-----------
In SlithIR, all arithmetic becomes `Binary` operations with an explicit
`BinaryType` (ADD, SUB, MUL, POWER, DIV). This is cleaner than parsing
source text for `+` symbols, which could match string concatenation or
comments.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from packaging.version import Version

from src.detectors import BaseDetector, Confidence, Finding, Severity

if TYPE_CHECKING:
    from slither.core.declarations import Contract, Function
    from slither.core.cfg.node import Node

logger = logging.getLogger(__name__)


# Arithmetic operations that can overflow/underflow
_OVERFLOW_TYPES: set[str] = {"ADD", "SUB", "MUL", "POWER"}


class IntegerOverflowDetector(BaseDetector):
    """Detects unchecked integer arithmetic in pre-0.8.0 contracts."""

    DETECTOR_ID = "SOLSCAN-002"
    TITLE = "Integer Overflow / Underflow"
    SEVERITY = Severity.HIGH
    CONFIDENCE = Confidence.MEDIUM
    DESCRIPTION = (
        "Arithmetic operations are performed without overflow/underflow "
        "protection. In Solidity < 0.8.0, this can silently wrap values, "
        "leading to incorrect balances, bypassed access controls, or "
        "token minting exploits."
    )

    _REFERENCES = [
        "https://swcregistry.io/docs/SWC-101",
        "https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/integer-overflow-and-underflow/",
    ]

    def detect(self, contract: Contract) -> list[Finding]:
        """
        Analyze a contract for unprotected arithmetic.

        Strategy:
        - Parse the pragma to determine the compiler version.
        - If >= 0.8.0, arithmetic is safe by default (skip unless unchecked).
        - If < 0.8.0, every Binary ADD/SUB/MUL/POWER is suspect unless
          SafeMath is imported or require() guards the result.
        """
        findings: list[Finding] = []

        compiler_version = self._get_compiler_version(contract)
        is_pre_080 = compiler_version < Version("0.8.0")
        uses_safemath = self._uses_safemath(contract)

        if is_pre_080 and uses_safemath:
            logger.info(
                "Contract %s uses SafeMath — skipping overflow analysis.",
                contract.name,
            )
            return findings

        for function in contract.functions_declared:
            if function.view or function.pure or function.is_constructor:
                continue
            if not function.nodes:
                continue

            func_findings = self._analyze_function(
                function,
                is_pre_080=is_pre_080,
            )
            findings.extend(func_findings)

        return findings

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_compiler_version(contract: Contract) -> Version:
        """
        Extract the Solidity compiler version from the contract's pragma.

        Falls back to 0.8.0 (safe default) if unparseable.
        """
        try:
            # Slither exposes the solc version used for compilation
            solc_version = contract.compilation_unit.compiler_version
            if solc_version:
                # Strip leading 'v' or '^' and any metadata
                cleaned = str(solc_version).lstrip("v^").split("+")[0].strip()
                return Version(cleaned)
        except Exception:
            logger.warning(
                "Could not determine compiler version for %s; assuming 0.8.0.",
                contract.name,
            )
        return Version("0.8.0")

    @staticmethod
    def _uses_safemath(contract: Contract) -> bool:
        """
        Heuristic: check if the contract inherits from or imports SafeMath.

        This isn't perfect (a contract could import SafeMath but not use it),
        but it eliminates the vast majority of false positives for pre-0.8.0
        contracts that already adopted the standard mitigation.
        """
        safemath_names = {"SafeMath", "SafeMath256", "SafeMath8", "SafeMath16"}

        # Check `using SafeMath for uint256`
        for using in contract.using_for:
            if hasattr(using, "name") and using.name in safemath_names:
                return True

        # Check direct inheritance
        for parent in contract.inheritance:
            if parent.name in safemath_names:
                return True

        return False

    def _analyze_function(
        self,
        func: Function,
        *,
        is_pre_080: bool,
    ) -> list[Finding]:
        """
        Walk SlithIR for a function and flag unchecked arithmetic.

        In pre-0.8.0 mode, every arithmetic Binary op is flagged.
        In >=0.8.0 mode, only operations inside `unchecked` scope
        are flagged (TODO: requires Slither's scope tracking).
        """
        from slither.slithir.operations import Binary

        findings: list[Finding] = []
        seen_lines: set[int] = set()  # deduplicate per line

        for node in func.nodes:
            for ir_op in node.irs:
                if not isinstance(ir_op, Binary):
                    continue

                op_type = str(ir_op.type).upper()
                if op_type not in _OVERFLOW_TYPES:
                    continue

                # For >= 0.8.0, only flag unchecked blocks
                if not is_pre_080:
                    if not self._is_in_unchecked_block(node):
                        continue

                line = (
                    node.source_mapping.get("lines", [0])[0]
                    if node.source_mapping
                    else 0
                )
                if line in seen_lines:
                    continue
                seen_lines.add(line)

                # Check if this specific operation has a require/assert guard
                if self._has_overflow_guard(node, func):
                    continue

                findings.append(
                    self._build_finding(func, node, op_type, is_pre_080)
                )

        return findings

    @staticmethod
    def _is_in_unchecked_block(node: Node) -> bool:
        """
        Check if a CFG node lives inside an `unchecked { }` block.

        Slither marks scope info on nodes. This is a best-effort check.
        """
        # Slither's node scope attribute (if available)
        scope = getattr(node, "scope", {})
        return bool(scope.get("unchecked", False))

    @staticmethod
    def _has_overflow_guard(node: Node, func: Function) -> bool:
        """
        Heuristic: check if the arithmetic result is guarded by require/assert.

        Walk subsequent nodes in the function looking for a SolidityCall
        to require() or assert() that references the same variable.
        """
        from slither.slithir.operations import SolidityCall

        lvalue = None
        for ir_op in node.irs:
            from slither.slithir.operations import Binary

            if isinstance(ir_op, Binary):
                lvalue = getattr(ir_op, "lvalue", None)
                break

        if lvalue is None:
            return False

        # Check downstream nodes for a require/assert using this value
        found_node = False
        for subsequent in func.nodes:
            if subsequent == node:
                found_node = True
                continue
            if not found_node:
                continue
            for ir_op in subsequent.irs:
                if isinstance(ir_op, SolidityCall):
                    call_name = str(ir_op.function)
                    if call_name in ("require(bool)", "require(bool,string)", "assert(bool)"):
                        # Check if the lvalue is referenced in the arguments
                        for arg in ir_op.arguments:
                            if arg == lvalue:
                                return True
        return False

    def _build_finding(
        self,
        func: Function,
        node: Node,
        op_type: str,
        is_pre_080: bool,
    ) -> Finding:
        """Construct a detailed Finding for an overflow vulnerability."""
        line = (
            node.source_mapping.get("lines", [0])[0]
            if node.source_mapping
            else 0
        )

        context = (
            "compiled with Solidity < 0.8.0 (no built-in overflow checks)"
            if is_pre_080
            else "inside an `unchecked` block"
        )

        description = (
            f"Function `{func.full_name}` in `{func.contract_declarer.name}` "
            f"performs a `{op_type}` operation at line {line} {context}. "
            f"This arithmetic could silently overflow or underflow."
        )

        recommendation = (
            "Use OpenZeppelin's SafeMath library (for < 0.8.0) or remove the "
            "`unchecked` block if overflow safety is required. Alternatively, "
            "upgrade the contract to Solidity >= 0.8.0."
            if is_pre_080
            else "Remove the `unchecked` block or add explicit bounds checking."
        )

        return self._make_finding(
            func=func,
            description=description,
            recommendation=recommendation,
            confidence=Confidence.MEDIUM if is_pre_080 else Confidence.HIGH,
            references=self._REFERENCES,
        )
