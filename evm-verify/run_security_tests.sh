#!/bin/bash

echo "🔒 COMPREHENSIVE ZODA SECURITY TESTING"
echo "======================================="
echo ""

echo "📋 Running tests in order:"
echo "  1. Basic soundness tests"
echo "  2. Security parameter audit"
echo "  3. Adversarial attack simulation"
echo ""

# Test 1: Soundness Tests
echo "🔒 TEST 1: SOUNDNESS TESTS"
echo "============================"
cargo test --test zoda_soundness_tests -- --nocapture --test-threads=1
SOUNDNESS_RESULT=$?

echo ""
echo ""

# Test 2: Security Audit
echo "🔒 TEST 2: SECURITY PARAMETER AUDIT"
echo "====================================="
cargo run --bin zoda_security_audit -- --detailed --audit-recommendations
AUDIT_RESULT=$?

echo ""
echo ""

# Test 3: Adversarial Testing
echo "🔒 TEST 3: ADVERSARIAL ATTACK SIMULATION"
echo "=========================================="
cargo run --bin tensorzoda_adversarial_tester -- --iterations 1000 --timing-analysis
ADVERSARIAL_RESULT=$?

echo ""
echo ""

# Summary
echo "📊 SECURITY TEST SUMMARY"
echo "========================"
echo ""

if [ $SOUNDNESS_RESULT -eq 0 ]; then
    echo "✅ Soundness Tests: PASSED"
else
    echo "❌ Soundness Tests: FAILED (Exit code: $SOUNDNESS_RESULT)"
fi

if [ $AUDIT_RESULT -eq 0 ]; then
    echo "✅ Security Audit: PASSED"
else
    echo "❌ Security Audit: FAILED (Exit code: $AUDIT_RESULT)"
fi

if [ $ADVERSARIAL_RESULT -eq 0 ]; then
    echo "✅ Adversarial Tests: PASSED"
else
    echo "❌ Adversarial Tests: FAILED (Exit code: $ADVERSARIAL_RESULT)"
fi

echo ""

# Overall result
if [ $SOUNDNESS_RESULT -eq 0 ] && [ $AUDIT_RESULT -eq 0 ] && [ $ADVERSARIAL_RESULT -eq 0 ]; then
    echo "🎉 ALL SECURITY TESTS PASSED"
    exit 0
else
    echo "⚠️  SOME SECURITY TESTS FAILED"
    echo ""
    echo "RECOMMENDATIONS:"
    echo "1. Review failed test output above"
    echo "2. Address any critical vulnerabilities"
    echo "3. Consider third-party cryptographic audit"
    exit 1
fi
