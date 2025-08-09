#!/bin/bash
# HTX Fuzzing Coverage Script
# Requirements: cargo-fuzz, grcov

set -e

echo "HTX Fuzz Testing and Coverage Analysis"
echo "======================================"

# Install required tools if not present
if ! command -v cargo-fuzz &> /dev/null; then
    echo "Installing cargo-fuzz..."
    cargo install cargo-fuzz
fi

if ! command -v grcov &> /dev/null; then
    echo "Installing grcov..."
    cargo install grcov
fi

# Create coverage directory
mkdir -p coverage

# Set up environment for coverage
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"
export RUSTDOCFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"

echo "Running unit tests with coverage..."
cargo clean
cargo +nightly test --lib --verbose

# Move to fuzz directory
cd fuzz

echo "Running fuzz tests..."

# Run each fuzz target for a reasonable duration
FUZZ_TARGETS=(
    "fuzz_frame_parsing"
    "fuzz_access_ticket"
    "fuzz_noise_handshake"
    "fuzz_flow_control"
    "fuzz_tls_fingerprinting"
)

for target in "${FUZZ_TARGETS[@]}"; do
    echo "Fuzzing $target for 30 seconds..."
    timeout 30s cargo +nightly fuzz run $target || true
    echo "Completed $target"
done

echo "Generating coverage report..."

# Collect coverage data
grcov . \
    --binary-path ./target/debug/ \
    -s . \
    -t html \
    --branch \
    --ignore-not-existing \
    --ignore "/*" \
    --ignore "*/tests/*" \
    --ignore "*/fuzz/*" \
    --ignore "*/target/*" \
    -o coverage/

# Generate lcov format for CI
grcov . \
    --binary-path ./target/debug/ \
    -s . \
    -t lcov \
    --branch \
    --ignore-not-existing \
    --ignore "/*" \
    --ignore "*/tests/*" \
    --ignore "*/fuzz/*" \
    --ignore "*/target/*" \
    -o coverage/lcov.info

echo "Coverage report generated in coverage/ directory"
echo "Open coverage/index.html to view detailed coverage"

# Parse coverage percentage
if command -v lcov &> /dev/null; then
    COVERAGE=$(lcov --summary coverage/lcov.info 2>&1 | grep -E "(lines|branches)" | tail -n1 | grep -o '[0-9.]*%' | head -n1)
    echo "Coverage: $COVERAGE"

    # Check if we meet the 80% requirement
    COVERAGE_NUM=$(echo $COVERAGE | grep -o '[0-9.]*')
    if (( $(echo "$COVERAGE_NUM >= 80.0" | bc -l) )); then
        echo "✅ Coverage requirement MET (≥80%): $COVERAGE"
        exit 0
    else
        echo "❌ Coverage requirement NOT MET (<80%): $COVERAGE"
        exit 1
    fi
else
    echo "Install lcov for coverage percentage calculation"
fi
