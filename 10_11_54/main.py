import argparse
import sys
from typing import Callable, Dict, List


def check_environment() -> None:
    if sys.version_info < (3, 11):
        sys.stderr.write(
            f"Error: Python 3.11 or later is required. Current version: {sys.version.split()[0]}\n"
        )
        sys.exit(2)
    try:
        import cryptography  # noqa: F401
    except ImportError:
        sys.stderr.write(
            "Error: Required dependency 'cryptography' is not installed.\n"
            "Install it using: pip install -r requirements.txt\n"
        )
        sys.exit(2)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=(
            "Educational simulation of X25519 Diffie-Hellman key agreement, "
            "Man-in-the-Middle attacks, Ed25519 authenticated key exchange, "
            "HKDF-SHA-256 key derivation, and AES-GCM tampering detection."
        ),
    )
    parser.add_argument(
        "scenario",
        choices=["normal", "mitm", "authenticated", "tamper", "all"],
        help="Select which cryptographic demonstration scenario to execute.",
    )
    return parser


def main(argv: List[str] | None = None) -> int:
    check_environment()

    from scenarios import (
        ScenarioOutcome,
        run_authenticated_scenario,
        run_mitm_scenario,
        run_normal_scenario,
        run_tamper_scenario,
    )

    parser = build_argument_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1

    scenario_dispatch: Dict[str, Callable[[bool], ScenarioOutcome]] = {
        "normal": run_normal_scenario,
        "mitm": run_mitm_scenario,
        "authenticated": run_authenticated_scenario,
        "tamper": run_tamper_scenario,
    }

    if args.scenario == "all":
        selected_Order = ["normal", "mitm", "authenticated", "tamper"]
    else:
        selected_Order = [args.scenario]

    outcomes: List[ScenarioOutcome] = []
    try:
        for name in selected_Order:
            outcome = scenario_dispatch[name](verbose=True)
            outcomes.append(outcome)
    except Exception as exc:
        sys.stderr.write(f"Fatal error during scenario execution: {exc}\n")
        return 1

    if len(outcomes) > 1:
        print("=" * 72)
        print("EXECUTION SUMMARY ACROSS ALL SCENARIOS")
        print("=" * 72)
        for item in outcomes:
            status_label = "[PASS]" if item.passed else "[FAIL]"
            print(f"Scenario '{item.scenario_name:<15}' : {status_label}")
        print("=" * 72)

    all_passed = all(item.passed for item in outcomes)
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())