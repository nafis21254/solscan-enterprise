#!/usr/bin/env bash
# ============================================================================
# SolScan Enterprise - Developer Bootstrap Script
# Sets up the full development environment from zero.
# Usage: chmod +x setup.sh && ./setup.sh
# ============================================================================
set -euo pipefail

PYTHON_MIN="3.10"
SOLC_VERSIONS=("0.7.6" "0.8.0" "0.8.20" "0.8.26")
SOLC_DEFAULT="0.8.26"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# ---- Step 1: Verify Python version ----
info "Checking Python version..."
PYTHON_VER=$(python3 --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo "$PYTHON_VER" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VER" | cut -d. -f2)

if [[ "$PYTHON_MAJOR" -lt 3 ]] || [[ "$PYTHON_MINOR" -lt 10 ]]; then
    fail "Python >= $PYTHON_MIN required. Found: $PYTHON_VER"
fi
info "Python $PYTHON_VER — OK"

# ---- Step 2: Create virtual environment ----
if [ ! -d ".venv" ]; then
    info "Creating virtual environment (.venv)..."
    python3 -m venv .venv
else
    warn "Virtual environment already exists, skipping."
fi

source .venv/bin/activate
info "Activated .venv ($(python --version))"

# ---- Step 3: Install dependencies ----
info "Upgrading pip..."
pip install --upgrade pip --quiet

info "Installing production dependencies..."
pip install -r requirements.txt --quiet

info "Installing dev dependencies..."
pip install -r requirements-dev.txt --quiet

# ---- Step 4: Install solc versions via solc-select ----
info "Installing Solidity compiler versions via solc-select..."
for version in "${SOLC_VERSIONS[@]}"; do
    if solc-select versions | grep -q "^${version}$" 2>/dev/null; then
        warn "solc $version already installed."
    else
        info "Installing solc $version..."
        solc-select install "$version" 2>/dev/null || warn "Failed to install solc $version"
    fi
done

info "Setting default solc to $SOLC_DEFAULT..."
solc-select use "$SOLC_DEFAULT" 2>/dev/null || warn "Could not set default solc"

# ---- Step 5: Verify installation ----
echo ""
info "============ Environment Ready ============"
echo "  Python:   $(python --version)"
echo "  Pip:      $(pip --version | awk '{print $2}')"
echo "  Slither:  $(slither --version 2>/dev/null || echo 'not found')"
echo "  solc:     $(solc --version 2>/dev/null | grep Version || echo 'not found')"
echo ""
info "Run tests:   pytest"
info "Run scanner: python -m src.main --help"
info "==========================================="
