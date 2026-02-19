"""
SARIF v2.1.0 Reporter
=====================

Converts SolScan findings into the Static Analysis Results Interchange
Format (SARIF), the industry standard consumed by:

  - GitHub Code Scanning ("Security" tab)
  - Azure DevOps
  - VS Code SARIF Viewer
  - DefectDojo, Semgrep, and other aggregators

SARIF Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/

Schema Structure
----------------
{
  "$schema": "...",
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name", "version", "rules": [...] } },
    "results": [{ "ruleId", "message", "locations", "level" }],
    "artifacts": [{ "location": { "uri": "..." } }]
  }]
}

This reporter builds the SARIF JSON from raw Python dicts (no sarif-om
dependency required, though it's compatible). This gives us full control
over the output and avoids version-lock issues with the sarif-om library.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src import __version__
from src.detectors import Finding, Severity

logger = logging.getLogger(__name__)

# SARIF v2.1.0 schema URI
_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)


class SarifReporter:
    """
    Converts a list of Finding objects into a SARIF v2.1.0 JSON document.

    Usage
    -----
    >>> reporter = SarifReporter(findings)
    >>> reporter.write("results.sarif")
    >>> # or get the dict directly:
    >>> sarif_dict = reporter.to_dict()
    """

    TOOL_NAME = "SolScan Enterprise"
    TOOL_URI = "https://github.com/yourname/solscan-enterprise"

    def __init__(self, findings: list[Finding]) -> None:
        self._findings = findings
        self._rules_index: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Build the complete SARIF document as a Python dict."""
        rules = self._build_rules()
        results = self._build_results()
        artifacts = self._build_artifacts()

        return {
            "$schema": _SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.TOOL_NAME,
                            "version": __version__,
                            "semanticVersion": __version__,
                            "informationUri": self.TOOL_URI,
                            "rules": rules,
                        },
                    },
                    "results": results,
                    "artifacts": artifacts,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                        }
                    ],
                    "columnKind": "utf16CodeUnits",
                }
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize the SARIF document to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def write(self, output_path: str | Path) -> Path:
        """
        Write the SARIF JSON to a file.

        Parameters
        ----------
        output_path : str | Path
            Destination file path (e.g., "results.sarif").

        Returns
        -------
        Path
            The resolved absolute path of the written file.
        """
        path = Path(output_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), encoding="utf-8")

        logger.info(
            "SARIF report written: %s (%d findings, %d rules)",
            path,
            len(self._findings),
            len(self._rules_index),
        )
        return path

    # ------------------------------------------------------------------
    # Private builders
    # ------------------------------------------------------------------

    def _build_rules(self) -> list[dict[str, Any]]:
        """
        Build the `tool.driver.rules[]` array.

        Each unique detector_id becomes one rule. We deduplicate by
        detector_id and track the index for result → rule mapping.
        """
        rules: list[dict[str, Any]] = []
        self._rules_index = {}

        for finding in self._findings:
            if finding.detector_id in self._rules_index:
                continue

            self._rules_index[finding.detector_id] = len(rules)

            rule: dict[str, Any] = {
                "id": finding.detector_id,
                "name": finding.title.replace(" ", ""),
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "defaultConfiguration": {
                    "level": finding.severity.value,
                },
                "properties": {
                    "tags": ["security", "solidity", "smart-contract"],
                    "precision": finding.confidence.value,
                },
            }

            if finding.references:
                rule["helpUri"] = finding.references[0]
                rule["help"] = {
                    "text": finding.recommendation or finding.description,
                    "markdown": self._build_help_markdown(finding),
                }

            rules.append(rule)

        return rules

    def _build_results(self) -> list[dict[str, Any]]:
        """
        Build the `runs[0].results[]` array.

        Each Finding becomes one SARIF result with:
        - ruleId + ruleIndex (links to the rule definition)
        - level (error/warning/note)
        - message
        - locations[] with physical location (file + line range)
        """
        results: list[dict[str, Any]] = []

        for finding in self._findings:
            result: dict[str, Any] = {
                "ruleId": finding.detector_id,
                "ruleIndex": self._rules_index.get(finding.detector_id, 0),
                "level": self._severity_to_sarif_level(finding.severity),
                "message": {"text": finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.filename,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": finding.line_start,
                                "endLine": finding.line_end,
                            },
                        },
                        "logicalLocations": [
                            {
                                "fullyQualifiedName": (
                                    f"{finding.contract_name}.{finding.function_name}"
                                ),
                                "kind": "function",
                            }
                        ],
                    }
                ],
            }

            # Add fix recommendation if available
            if finding.recommendation:
                result["fixes"] = [
                    {
                        "description": {"text": finding.recommendation},
                    }
                ]

            results.append(result)

        return results

    def _build_artifacts(self) -> list[dict[str, Any]]:
        """
        Build the `runs[0].artifacts[]` array.

        Lists all unique source files referenced by findings.
        """
        seen_files: set[str] = set()
        artifacts: list[dict[str, Any]] = []

        for finding in self._findings:
            if finding.filename not in seen_files:
                seen_files.add(finding.filename)
                artifacts.append(
                    {
                        "location": {
                            "uri": finding.filename,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "sourceLanguage": "solidity",
                    }
                )

        return artifacts

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _severity_to_sarif_level(severity: Severity) -> str:
        """Map our Severity enum to SARIF level strings."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }
        return mapping.get(severity, "warning")

    @staticmethod
    def _build_help_markdown(finding: Finding) -> str:
        """Build a rich help message in Markdown for SARIF viewers."""
        lines = [
            f"## {finding.title}",
            "",
            finding.description,
            "",
            "### Recommendation",
            "",
            finding.recommendation or "No specific recommendation.",
            "",
        ]

        if finding.references:
            lines.append("### References")
            lines.append("")
            for ref in finding.references:
                lines.append(f"- [{ref}]({ref})")

        return "\n".join(lines)
