"""
SolScan Enterprise — Orchestrator (Entry Point)
================================================

This module is the "conductor" that:
  1. Accepts CLI arguments (target path, output format, solc version).
  2. Initializes Slither against the target contract(s).
  3. Discovers and instantiates all registered detectors.
  4. Runs each detector against every contract in the compilation unit.
  5. Collects findings and passes them to the SARIF reporter.

Usage
-----
    # Scan a single file
    python -m src.main scan contracts/Vault.sol --output results.sarif

    # Scan with a specific solc version
    python -m src.main scan contracts/ --solc-version 0.7.6

    # List available detectors
    python -m src.main list-detectors
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from src import __version__
from src.detectors import BaseDetector, Finding
from src.detectors.integer_overflow import IntegerOverflowDetector
from src.detectors.reentrancy import ReentrancyDetector
from src.reporters.sarif_reporter import SarifReporter

logger = logging.getLogger("solscan")
console = Console()

# ---------------------------------------------------------------------------
# Detector Registry — add new detectors here
# ---------------------------------------------------------------------------
DETECTOR_REGISTRY: list[type[BaseDetector]] = [
    ReentrancyDetector,
    IntegerOverflowDetector,
]


# ---------------------------------------------------------------------------
# CLI Application
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(version=__version__, prog_name="SolScan Enterprise")
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable debug logging.",
)
def cli(verbose: bool) -> None:
    """SolScan Enterprise — SAST for Solidity Smart Contracts."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option(
    "--output", "-o",
    default="solscan-results.sarif",
    help="Output SARIF file path.",
    type=click.Path(),
)
@click.option(
    "--solc-version",
    default=None,
    help="Override solc version (e.g., '0.7.6'). Auto-detected if omitted.",
)
@click.option(
    "--exclude",
    multiple=True,
    help="Detector IDs to exclude (e.g., --exclude SOLSCAN-002).",
)
def scan(
    target: str,
    output: str,
    solc_version: str | None,
    exclude: tuple[str, ...],
) -> None:
    """Scan Solidity source files for vulnerabilities."""
    console.print(
        f"\n[bold blue]SolScan Enterprise v{__version__}[/bold blue]",
        highlight=False,
    )
    console.print(f"  Target:  {target}")
    console.print(f"  Output:  {output}\n")

    # ---- Step 1: Initialize Slither ----
    console.print("[bold]Phase 1:[/bold] Compiling with Slither...")
    start = time.monotonic()

    try:
        from slither.slither import Slither

        slither_args: dict[str, str] = {}
        if solc_version:
            slither_args["solc"] = solc_version

        slither = Slither(target, **slither_args)

    except ImportError:
        console.print("[red]Error:[/red] slither-analyzer is not installed.")
        console.print("  Run: pip install slither-analyzer")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] Slither compilation failed: {e}")
        sys.exit(1)

    compile_time = time.monotonic() - start
    console.print(f"  Compiled in {compile_time:.2f}s\n")

    # ---- Step 2: Instantiate detectors ----
    exclude_set = set(exclude)
    active_detectors = [
        det_cls()
        for det_cls in DETECTOR_REGISTRY
        if det_cls.DETECTOR_ID not in exclude_set
    ]

    console.print(
        f"[bold]Phase 2:[/bold] Running {len(active_detectors)} detectors...\n"
    )

    # ---- Step 3: Run detectors against all contracts ----
    all_findings: list[Finding] = []

    for contract in slither.contracts_derived:
        for detector in active_detectors:
            try:
                findings = detector.detect(contract)
                all_findings.extend(findings)

                if findings:
                    for f in findings:
                        console.print(
                            f"  [{f.severity.value.upper()}] {f.detector_id}: "
                            f"{f.contract_name}.{f.function_name} "
                            f"({f.location_str})"
                        )

            except Exception as e:
                logger.error(
                    "Detector %s crashed on %s: %s",
                    detector.DETECTOR_ID,
                    contract.name,
                    e,
                    exc_info=True,
                )

    # ---- Step 4: Generate report ----
    console.print(f"\n[bold]Phase 3:[/bold] Generating SARIF report...")

    reporter = SarifReporter(all_findings)
    output_path = reporter.write(output)

    # ---- Summary ----
    _print_summary(all_findings, output_path, time.monotonic() - start)

    # Exit code: non-zero if critical/high findings exist
    has_critical = any(
        f.severity in {Finding.severity.CRITICAL, Finding.severity.HIGH}  # type: ignore[attr-defined]
        for f in all_findings
    ) if all_findings else False

    sys.exit(1 if has_critical else 0)


@cli.command("list-detectors")
def list_detectors() -> None:
    """Show all available detectors and their metadata."""
    table = Table(title="SolScan Enterprise — Detector Registry")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Title", style="white")
    table.add_column("Severity", style="red")
    table.add_column("Confidence", style="yellow")

    for det_cls in DETECTOR_REGISTRY:
        table.add_row(
            det_cls.DETECTOR_ID,
            det_cls.TITLE,
            det_cls.SEVERITY.name,
            det_cls.CONFIDENCE.name,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_summary(
    findings: list[Finding],
    output_path: Path,
    elapsed: float,
) -> None:
    """Print a colored summary table to the terminal."""
    console.print()

    table = Table(title="Scan Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value")

    severity_counts = {}
    for f in findings:
        key = f.severity.name
        severity_counts[key] = severity_counts.get(key, 0) + 1

    table.add_row("Total Findings", str(len(findings)))
    for sev, count in sorted(severity_counts.items()):
        table.add_row(f"  {sev}", str(count))
    table.add_row("Report", str(output_path))
    table.add_row("Time", f"{elapsed:.2f}s")

    console.print(table)

    if not findings:
        console.print("\n[bold green]✓ No vulnerabilities detected.[/bold green]\n")
    else:
        console.print(
            f"\n[bold yellow]⚠ {len(findings)} finding(s) require review.[/bold yellow]\n"
        )


# ---------------------------------------------------------------------------
# Direct execution support
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
