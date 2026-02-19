"""
Base Detector — Abstract interface for all SolScan vulnerability detectors.

Every detector inherits from this class. The Orchestrator discovers and
instantiates detectors dynamically, so new detectors are added by simply
dropping a new file in src/detectors/ — zero changes to main.py.

Architecture Notes
------------------
Slither compiles Solidity → an AST → SlithIR (its intermediate representation).
SlithIR breaks every Solidity statement into typed operations:

    HighLevelCall   — external .call()/.send()/.transfer()
    LowLevelCall    — address.call{value: ...}("")
    InternalCall    — calls within the same contract
    SolidityCall    — require(), assert(), revert()
    Assignment      — state variable writes
    Binary          — arithmetic: +, -, *, /
    Condition       — if-statement guards

Our detectors walk these IR operations instead of regex-matching source code,
which gives us semantic precision that source-pattern tools cannot achieve.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from slither.core.declarations import Contract, Function
    from slither.slithir.operations import Operation

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Types
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """SARIF-compatible severity levels."""

    CRITICAL = "error"
    HIGH = "error"
    MEDIUM = "warning"
    LOW = "note"
    INFO = "none"


class Confidence(str, Enum):
    """How certain we are this is a true positive."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, slots=True)
class Finding:
    """
    An immutable, self-contained vulnerability finding.

    Every detector returns a list of these. The Reporter converts them
    into SARIF result objects downstream — detectors never touch SARIF.
    """

    detector_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    contract_name: str
    function_name: str
    filename: str
    line_start: int
    line_end: int
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def location_str(self) -> str:
        return f"{self.filename}:{self.line_start}-{self.line_end}"


# ---------------------------------------------------------------------------
# Abstract Base Detector
# ---------------------------------------------------------------------------

class BaseDetector(ABC):
    """
    Abstract base for all SolScan detectors.

    Subclasses MUST implement:
        - DETECTOR_ID   (class var)  — unique slug, e.g. "SOLSCAN-001"
        - TITLE         (class var)  — human-readable name
        - SEVERITY      (class var)  — default severity
        - DESCRIPTION   (class var)  — one-paragraph explanation
        - detect(contract) -> list[Finding]

    The Orchestrator calls `detect()` once per contract in the compilation
    unit. The detector is free to inspect any part of the Slither object
    model: contract → functions → nodes → IR operations.
    """

    # Subclasses must override these class-level constants.
    DETECTOR_ID: str = ""
    TITLE: str = ""
    SEVERITY: Severity = Severity.MEDIUM
    CONFIDENCE: Confidence = Confidence.MEDIUM
    DESCRIPTION: str = ""

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Validate that subclasses define required metadata."""
        super().__init_subclass__(**kwargs)
        if not getattr(cls, "DETECTOR_ID", ""):
            raise TypeError(f"{cls.__name__} must define DETECTOR_ID")
        if not getattr(cls, "TITLE", ""):
            raise TypeError(f"{cls.__name__} must define TITLE")

    # ---- Public API ----

    @abstractmethod
    def detect(self, contract: Contract) -> list[Finding]:
        """
        Run this detector against a single Solidity contract.

        Parameters
        ----------
        contract : slither.core.declarations.Contract
            A fully-parsed Slither contract object with access to
            functions, state variables, and the SlithIR.

        Returns
        -------
        list[Finding]
            Zero or more findings. Empty list = contract is clean
            for this detector's vulnerability class.
        """
        ...

    # ---- Utility helpers available to all detectors ----

    @staticmethod
    def get_source_lines(func: Function) -> tuple[str, int, int]:
        """
        Extract the filename and line range for a function.

        Returns
        -------
        tuple[str, int, int]
            (filename, start_line, end_line)
        """
        source = func.source_mapping
        filename = source.get("filename_relative", source.get("filename_absolute", "unknown"))
        start = source.get("lines", [0])[0] if source.get("lines") else 0
        end = source.get("lines", [0])[-1] if source.get("lines") else 0
        return filename, start, end

    @staticmethod
    def is_external_call(op: Operation) -> bool:
        """Check if an IR operation is an external call (ETH transfer or call)."""
        from slither.slithir.operations import HighLevelCall, LowLevelCall, Send, Transfer

        return isinstance(op, (HighLevelCall, LowLevelCall, Send, Transfer))

    @staticmethod
    def is_state_write(op: Operation) -> bool:
        """Check if an IR operation writes to a state variable."""
        from slither.slithir.operations import Assignment, Binary

        if isinstance(op, (Assignment, Binary)):
            written = getattr(op, "lvalue", None)
            if written is not None:
                from slither.core.variables.state_variable import StateVariable

                return isinstance(written, StateVariable)
        return False

    def _make_finding(
        self,
        func: Function,
        description: str,
        recommendation: str = "",
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        references: list[str] | None = None,
    ) -> Finding:
        """
        Convenience factory — builds a Finding pre-filled with detector
        metadata and function location info.
        """
        filename, line_start, line_end = self.get_source_lines(func)
        return Finding(
            detector_id=self.DETECTOR_ID,
            title=self.TITLE,
            description=description,
            severity=severity or self.SEVERITY,
            confidence=confidence or self.CONFIDENCE,
            contract_name=func.contract_declarer.name,
            function_name=func.full_name,
            filename=filename,
            line_start=line_start,
            line_end=line_end,
            recommendation=recommendation,
            references=references or [],
        )
