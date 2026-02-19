"""
Unit tests for the BaseDetector and Finding data model.

These test the architectural foundations without requiring Slither.
"""

from __future__ import annotations

import pytest

from src.detectors import BaseDetector, Confidence, Finding, Severity


class TestFinding:
    """Test the Finding dataclass."""

    def test_finding_is_immutable(self, sample_finding: Finding) -> None:
        """Findings should be frozen (immutable)."""
        with pytest.raises(AttributeError):
            sample_finding.title = "Modified"  # type: ignore[misc]

    def test_location_str(self, sample_finding: Finding) -> None:
        """location_str should format as 'file:start-end'."""
        expected = "contracts/VulnerableVault.sol:14-23"
        assert sample_finding.location_str == expected

    def test_severity_values(self) -> None:
        """Severity enum values should be SARIF-compatible."""
        assert Severity.CRITICAL.value == "error"
        assert Severity.MEDIUM.value == "warning"
        assert Severity.LOW.value == "note"
        assert Severity.INFO.value == "none"

    def test_finding_defaults(self) -> None:
        """Optional fields should have sensible defaults."""
        f = Finding(
            detector_id="TEST-001",
            title="Test",
            description="Test finding",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            contract_name="Test",
            function_name="test()",
            filename="test.sol",
            line_start=1,
            line_end=1,
        )
        assert f.recommendation == ""
        assert f.references == []
        assert f.metadata == {}


class TestBaseDetector:
    """Test the abstract BaseDetector class."""

    def test_subclass_requires_detector_id(self) -> None:
        """Subclasses without DETECTOR_ID should raise TypeError."""
        with pytest.raises(TypeError, match="DETECTOR_ID"):

            class BadDetector(BaseDetector):  # type: ignore[type-var]
                TITLE = "Has a title"

                def detect(self, contract):  # type: ignore[override]
                    return []

    def test_subclass_requires_title(self) -> None:
        """Subclasses without TITLE should raise TypeError."""
        with pytest.raises(TypeError, match="TITLE"):

            class BadDetector(BaseDetector):  # type: ignore[type-var]
                DETECTOR_ID = "TEST-001"

                def detect(self, contract):  # type: ignore[override]
                    return []

    def test_valid_subclass_instantiates(self) -> None:
        """A properly defined subclass should instantiate without error."""

        class GoodDetector(BaseDetector):
            DETECTOR_ID = "TEST-001"
            TITLE = "Test Detector"

            def detect(self, contract):  # type: ignore[override]
                return []

        detector = GoodDetector()
        assert detector.DETECTOR_ID == "TEST-001"
