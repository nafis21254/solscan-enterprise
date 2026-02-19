"""
Unit tests for the SARIF v2.1.0 Reporter.

These tests validate the SARIF output structure WITHOUT requiring Slither
or solc — they use the mock Finding fixtures from conftest.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.detectors import Finding, Severity
from src.reporters.sarif_reporter import SarifReporter


class TestSarifStructure:
    """Verify the SARIF document matches the v2.1.0 schema."""

    def test_top_level_schema(self, sample_findings: list[Finding]) -> None:
        """SARIF must have $schema, version, and runs[]."""
        sarif = SarifReporter(sample_findings).to_dict()

        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert "sarif-schema-2.1.0.json" in sarif["$schema"]
        assert len(sarif["runs"]) == 1

    def test_tool_driver_metadata(self, sample_findings: list[Finding]) -> None:
        """The tool.driver must contain name, version, and rules."""
        driver = SarifReporter(sample_findings).to_dict()["runs"][0]["tool"]["driver"]

        assert driver["name"] == "SolScan Enterprise"
        assert "version" in driver
        assert isinstance(driver["rules"], list)
        assert len(driver["rules"]) > 0

    def test_rules_deduplication(self, sample_findings: list[Finding]) -> None:
        """Each unique detector_id should produce exactly one rule."""
        sarif = SarifReporter(sample_findings).to_dict()
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]

        assert len(rule_ids) == len(set(rule_ids)), "Duplicate rule IDs found"
        assert "SOLSCAN-001" in rule_ids
        assert "SOLSCAN-002" in rule_ids

    def test_results_count_matches_findings(
        self, sample_findings: list[Finding]
    ) -> None:
        """Number of SARIF results must equal number of input findings."""
        sarif = SarifReporter(sample_findings).to_dict()
        results = sarif["runs"][0]["results"]

        assert len(results) == len(sample_findings)

    def test_result_has_location(self, sample_finding: Finding) -> None:
        """Each result must have a physicalLocation with file and line range."""
        sarif = SarifReporter([sample_finding]).to_dict()
        result = sarif["runs"][0]["results"][0]
        location = result["locations"][0]["physicalLocation"]

        assert location["artifactLocation"]["uri"] == sample_finding.filename
        assert location["region"]["startLine"] == sample_finding.line_start
        assert location["region"]["endLine"] == sample_finding.line_end

    def test_severity_mapping(self, sample_finding: Finding) -> None:
        """CRITICAL severity should map to SARIF level 'error'."""
        sarif = SarifReporter([sample_finding]).to_dict()
        result = sarif["runs"][0]["results"][0]

        assert result["level"] == "error"

    def test_empty_findings_produces_valid_sarif(self) -> None:
        """An empty findings list should still produce a valid SARIF doc."""
        sarif = SarifReporter([]).to_dict()

        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


class TestSarifSerialization:
    """Test JSON output and file writing."""

    def test_to_json_is_valid(self, sample_findings: list[Finding]) -> None:
        """to_json() must produce valid JSON."""
        json_str = SarifReporter(sample_findings).to_json()
        parsed = json.loads(json_str)

        assert parsed["version"] == "2.1.0"

    def test_write_creates_file(
        self, sample_findings: list[Finding], tmp_path: Path
    ) -> None:
        """write() must create a .sarif file on disk."""
        output = tmp_path / "results.sarif"
        returned_path = SarifReporter(sample_findings).write(output)

        assert output.exists()
        assert returned_path == output.resolve()

        content = json.loads(output.read_text())
        assert content["version"] == "2.1.0"

    def test_write_creates_parent_directories(
        self, sample_findings: list[Finding], tmp_path: Path
    ) -> None:
        """write() should create intermediate directories."""
        output = tmp_path / "nested" / "deep" / "results.sarif"
        SarifReporter(sample_findings).write(output)

        assert output.exists()


class TestSarifArtifacts:
    """Test the artifacts[] section (source file listing)."""

    def test_artifacts_lists_unique_files(
        self, sample_findings: list[Finding]
    ) -> None:
        """Artifacts should list each source file exactly once."""
        sarif = SarifReporter(sample_findings).to_dict()
        artifacts = sarif["runs"][0]["artifacts"]
        uris = [a["location"]["uri"] for a in artifacts]

        # Both findings reference the same file in our fixtures
        assert len(uris) == len(set(uris))

    def test_artifacts_source_language(self, sample_finding: Finding) -> None:
        """Artifacts should declare sourceLanguage as 'solidity'."""
        sarif = SarifReporter([sample_finding]).to_dict()
        artifact = sarif["runs"][0]["artifacts"][0]

        assert artifact["sourceLanguage"] == "solidity"
