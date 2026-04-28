#!/bin/bash
# macOS Test Runner - runs tests individually to avoid XCTest suite crash
# Issue: swift test (full suite) crashes with signal 5 after ~20 tests
# Workaround: run each test separately - all pass individually

set -e  # Exit on first failure

echo "Running macOS test suite (individual test mode)..."

# Track results
PASSED=0
FAILED=0

run_test() {
    local test_name=$1
    echo -n "  $test_name... "
    if swift test --filter "$test_name" > /dev/null 2>&1; then
        echo "✅"
        ((PASSED++))
    else
        echo "❌"
        ((FAILED++))
        echo "FAILED: $test_name" >> /tmp/test-failures.log
    fi
}

# Clean previous results
rm -f /tmp/test-failures.log

echo "LowSTests (8 tests):"
run_test "testEmptySignatureFails"
run_test "testExactlyHalfOrderIsValid"
run_test "testLowSSignatureUnchanged"
run_test "testMaxHighSSignature"
run_test "testNormalizationIsDeterministic"
run_test "testNormalizeTwiceIsIdempotent"
run_test "testOversizedSignatureFails"
run_test "testTruncatedSignatureFails"

echo ""
echo "PictogramTests (11 tests):"
run_test "testAllZerosFingerprint"
run_test "testDeterministicDerivation"
run_test "testEmojiListHas64Entries"
run_test "testEmojiListMatches"
run_test "testEmptyFingerprintFails"
run_test "testMaxFingerprint"
run_test "testSequentialIndices"
run_test "testShortFingerprintFails"
run_test "testSpeakableUsesSpacesNotHyphens"
run_test "testURLSafeFormUsesHyphens"
run_test "testVectorFromProtocolSpec"

echo ""
echo "RelayClientIntegrationTests (11 tests):"
run_test "testSuccessfulAuthentication"
run_test "testFingerprintMatchesPublicKey"
run_test "testAuthenticationUsesECDSAP256"
run_test "testConcurrentConnectionAttempts"
run_test "testGracefulDisconnect"
run_test "testStateTransitions"
run_test "testInvalidEndpoint"
run_test "testUnreachableEndpoint"
run_test "testPublicKeyIsCompressed"
run_test "testNotificationCallback"
run_test "testLongRunningConnection"

echo ""
echo "========================================"
echo "Results: $PASSED passed, $FAILED failed"
echo "========================================"

if [ $FAILED -gt 0 ]; then
    echo ""
    echo "Failed tests:"
    cat /tmp/test-failures.log
    exit 1
fi

echo "✅ All tests passed!"
exit 0
