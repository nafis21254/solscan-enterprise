<div align="center">

# SolScan Enterprise

**Static Analysis Security Testing for Solidity Smart Contracts**

[![CI](https://github.com/yourname/solscan-enterprise/actions/workflows/ci.yml/badge.svg)](https://github.com/yourname/solscan-enterprise/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![SARIF](https://img.shields.io/badge/output-SARIF%20v2.1.0-green.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

A modular, enterprise-grade SAST tool built on the [Slither](https://github.com/crytic/slither) framework. SolScan detects critical smart contract vulnerabilities using **SlithIR semantic analysis** and exports results in the industry-standard SARIF format for direct integration with GitHub Code Scanning, Azure DevOps, and CI/CD pipelines.

</div>

---

## Why SolScan?

Most Solidity linters rely on regex or AST pattern matching. SolScan operates on **Slither's Intermediate Representation (SlithIR)**, which decomposes every Solidity statement into typed operations (`HighLevelCall`, `Assignment`, `Binary`, etc.). This gives us **semantic precision**: we track data flow through the control-flow graph, not text patterns.

**Key Differentiators:**

- **SlithIR-based detection** — Analyzes compiled IR, not source text. Catches vulnerabilities that regex tools miss.
- **Modular detector architecture** — Each vulnerability class is a self-contained plugin. Add new detectors without touching the core engine.
- **SARIF v2.1.0 native output** — Results appear directly in the GitHub "Security" tab. Zero config.
- **CI/CD first** — Ships with a GitHub Actions workflow that scans every PR automatically.
- **Multi-version Solidity support** — Handles contracts from 0.4.x to 0.8.x via `solc-select`.

## Detectors

| ID | Vulnerability | Severity | Description |
|----|--------------|----------|-------------|
| `SOLSCAN-001` | **Reentrancy** (CEI Violation) | Critical | Identifies functions that make external calls before updating state variables, violating the Check-Effects-Interactions pattern. |
| `SOLSCAN-002` | **Integer Overflow/Underflow** | High | Flags unchecked arithmetic in contracts compiled with Solidity < 0.8.0, or inside `unchecked {}` blocks in >= 0.8.0. |

## Architecture

```
src/
├── main.py                      # CLI orchestrator (Click-based)
├── detectors/
│   ├── __init__.py              # BaseDetector ABC + Finding dataclass
│   ├── reentrancy.py            # SOLSCAN-001: CEI violation detector
│   └── integer_overflow.py      # SOLSCAN-002: Overflow/underflow detector
├── reporters/
│   └── sarif_reporter.py        # SARIF v2.1.0 JSON generator
└── utils/
    └── __init__.py              # Shared utilities
```

The system follows a **pipeline architecture**:

```
Solidity Source → Slither Compiler → SlithIR → Detectors → Findings → SARIF Reporter → .sarif
```

Each detector inherits from `BaseDetector` and implements a single `detect(contract) → list[Finding]` method. The orchestrator discovers detectors from a registry, runs them against every contract in the compilation unit, and pipes the collected findings to the reporter.

## Quick Start

### Prerequisites

- Python 3.10+
- A C compiler (for solc binary compilation)

### Installation

```bash
git clone https://github.com/yourname/solscan-enterprise.git
cd solscan-enterprise

# Automated setup (creates venv, installs deps, configures solc)
chmod +x setup.sh && ./setup.sh

# Or manually:
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
solc-select install 0.8.26 && solc-select use 0.8.26
```

### Usage

```bash
# Scan a single contract
python -m src.main scan contracts/MyToken.sol

# Scan with specific solc version (for older contracts)
python -m src.main scan contracts/LegacyVault.sol --solc-version 0.7.6

# Custom output path
python -m src.main scan contracts/ --output report.sarif

# Exclude specific detectors
python -m src.main scan contracts/ --exclude SOLSCAN-002

# List available detectors
python -m src.main list-detectors

# Verbose mode (debug logging)
python -m src.main -v scan contracts/MyToken.sol
```

### Example Output

```
SolScan Enterprise v1.0.0
  Target:  tests/fixtures/VulnerableVault.sol
  Output:  solscan-results.sarif

Phase 1: Compiling with Slither...
  Compiled in 1.42s

Phase 2: Running 2 detectors...

  [ERROR] SOLSCAN-001: VulnerableVault.withdraw() (VulnerableVault.sol:14-23)
  [ERROR] SOLSCAN-002: VulnerableVault.deposit() (VulnerableVault.sol:29-31)
  [ERROR] SOLSCAN-002: VulnerableVault.transfer(address,uint256) (VulnerableVault.sol:33-38)

Phase 3: Generating SARIF report...

┌─────────────────────────┐
│      Scan Summary       │
├───────────┬─────────────┤
│ Metric    │ Value       │
├───────────┼─────────────┤
│ Total     │ 3           │
│ CRITICAL  │ 1           │
│ HIGH      │ 2           │
│ Report    │ results.sarif│
│ Time      │ 2.14s       │
└───────────┴─────────────┘

⚠ 3 finding(s) require review.
```

## CI/CD Integration

SolScan ships with a GitHub Actions workflow (`.github/workflows/ci.yml`) that:

1. **Lints** the codebase with Ruff and MyPy
2. **Tests** across Python 3.10/3.11/3.12 with coverage
3. **Scans** test fixtures with SolScan
4. **Uploads** SARIF results to the GitHub "Security" tab automatically

To enable: push to a GitHub repo with Actions enabled. Results appear under **Security → Code scanning alerts**.

## Extending SolScan

Adding a new detector takes three steps:

1. Create `src/detectors/my_detector.py`:

```python
from src.detectors import BaseDetector, Finding, Severity, Confidence

class MyDetector(BaseDetector):
    DETECTOR_ID = "SOLSCAN-003"
    TITLE = "My Vulnerability"
    SEVERITY = Severity.HIGH
    CONFIDENCE = Confidence.MEDIUM
    DESCRIPTION = "Detects ..."

    def detect(self, contract) -> list[Finding]:
        findings = []
        # Your SlithIR analysis here
        return findings
```

2. Register it in `src/main.py`:

```python
from src.detectors.my_detector import MyDetector
DETECTOR_REGISTRY.append(MyDetector)
```

3. Add test fixtures and unit tests.

## Running Tests

```bash
# Unit tests (no solc required)
pytest tests/unit/ -v

# With coverage
pytest tests/unit/ --cov=src --cov-report=term-missing

# Integration tests (requires solc)
pytest tests/ -v -m integration
```

## Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Analysis Engine | [Slither](https://github.com/crytic/slither) + SlithIR | Semantic analysis of Solidity bytecode |
| CLI | [Click](https://click.palletsprojects.com/) + [Rich](https://rich.readthedocs.io/) | Professional terminal UX |
| Output Format | [SARIF v2.1.0](https://sarifweb.azurewebsites.net/) | Industry-standard security reporting |
| CI/CD | GitHub Actions | Automated scanning on every PR |
| Testing | pytest + coverage | Unit and integration testing |
| Linting | Ruff + MyPy + Bandit | Code quality + type safety + security |

## License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built as a demonstration of DevSecOps engineering, smart contract security analysis, and Python software architecture.**

</div>
