#!/usr/bin/env bash
set -euo pipefail

# run_tests.sh — Build and run the Guardian FS unit test suite
# Returns exit code 0 if all tests pass, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"

echo "==> Configuring test build..."
cmake -S "$PROJECT_ROOT" -B "$BUILD_DIR" -DBUILD_TESTS=ON

echo "==> Building tests..."
cmake --build "$BUILD_DIR" --target all --parallel "$(nproc 2>/dev/null || echo 4)"

echo ""
echo "==> Running tests..."
cd "$BUILD_DIR"
ctest --output-on-failure --test-dir tests/unit

CTEST_EXIT=$?
echo ""
if [[ $CTEST_EXIT -eq 0 ]]; then
    echo "==> All tests PASSED"
else
    echo "==> Some tests FAILED (exit code: $CTEST_EXIT)"
fi
exit $CTEST_EXIT
