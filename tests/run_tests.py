#!/usr/bin/env python3
"""
Test runner for netcon-sync.

Usage:
    ./tests/run_tests.py              Run all unit tests
    ./tests/run_tests.py --live       Run integration tests (requires live controller)
    ./tests/run_tests.py --regression Run regression tests
    ./tests/run_tests.py --help       Show this help
"""

import argparse
import subprocess
import sys
from pathlib import Path


def run_tests(test_path, extra_args=None):
    """Run pytest on the specified test path."""
    cmd = [sys.executable, "-m", "pytest", test_path]

    if extra_args:
        cmd.extend(extra_args)

    print(f"Running: {' '.join(cmd)}\n")
    print("=" * 70)

    result = subprocess.run(cmd)
    return result.returncode


def main():
    parser = argparse.ArgumentParser(
        description="Test runner for netcon-sync",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    ./tests/run_tests.py                    Run all unit tests
    ./tests/run_tests.py --live             Run integration tests
    ./tests/run_tests.py --regression       Run regression tests
    ./tests/run_tests.py -v                 Verbose output
    ./tests/run_tests.py --live -v          Verbose integration tests
        """
    )

    parser.add_argument(
        "--live",
        action="store_true",
        help="Run integration tests (requires live controller)"
    )

    parser.add_argument(
        "--regression",
        action="store_true",
        help="Run regression tests"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )

    parser.add_argument(
        "--unit",
        action="store_true",
        help="Run only unit tests (default)"
    )

    args = parser.parse_args()

    # Determine which tests to run
    unit_tests = True
    integration_tests = False
    regression_tests = False

    if args.unit and not (args.live or args.regression):
        unit_tests = True
    elif args.live:
        integration_tests = True
    elif args.regression:
        regression_tests = True
    else:
        # Default: run unit tests
        unit_tests = True

    extra_args = []
    if args.verbose:
        extra_args.append("-v")

    all_passed = True

    # Run unit tests
    if unit_tests:
        print("\n" + "=" * 70)
        print("RUNNING UNIT TESTS")
        print("=" * 70 + "\n")

        result = run_tests(
            "tests/unit",
            extra_args + ["-m", "unit"]
        )

        if result != 0:
            all_passed = False

    # Run integration tests
    if integration_tests:
        print("\n" + "=" * 70)
        print("RUNNING INTEGRATION TESTS")
        print("=" * 70 + "\n")

        result = run_tests(
            "tests/functional",
            extra_args + ["-m", "integration", "--live-controller"]
        )

        if result != 0:
            all_passed = False

    # Run regression tests
    if regression_tests:
        print("\n" + "=" * 70)
        print("RUNNING REGRESSION TESTS")
        print("=" * 70 + "\n")

        result = run_tests(
            "tests/functional",
            extra_args + ["-m", "regression"]
        )

        if result != 0:
            all_passed = False

    # Summary
    print("\n" + "=" * 70)
    if all_passed:
        print("ALL TESTS PASSED")
        return 0
    else:
        print("SOME TESTS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
