#!/usr/bin/env python3
"""Command-line interface for the zip analyzer."""

import sys

from zip_analyzer import ZipAnalyzer
from zip_analyzer.models import Severity

SEVERITY_COLORS = {
    Severity.INFO: "\033[36m",      # cyan
    Severity.LOW: "\033[32m",       # green
    Severity.MEDIUM: "\033[33m",    # yellow
    Severity.HIGH: "\033[91m",      # bright red
    Severity.CRITICAL: "\033[1;91m", # bold bright red
}
RESET = "\033[0m"


def colored(severity: Severity, text: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{SEVERITY_COLORS[severity]}{text}{RESET}"


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <zipfile> [zipfile ...]")
        sys.exit(1)

    use_color = sys.stdout.isatty()
    analyzer = ZipAnalyzer()
    exit_code = 0

    for path in sys.argv[1:]:
        print(f"\nAnalyzing: {path}")
        print("-" * 60)

        result = analyzer.analyze(path)

        if result.error:
            print(f"  ERROR: {result.error}")
            exit_code = 2
            continue

        if not result.findings:
            print("  No issues found.")
        else:
            for finding in sorted(result.findings, key=lambda f: f.severity, reverse=True):
                sev_tag = colored(finding.severity, f"[{finding.severity.value.upper()}]", use_color)
                loc = f" \033[2m{finding.filename}\033[0m" if finding.filename and use_color else (f" {finding.filename}" if finding.filename else "")
                detail = f"\n    {finding.detail}" if finding.detail else ""
                print(f"  {sev_tag} {finding.check}{loc}")
                print(f"    {finding.description}{detail}")

        verdict_color = "\033[92m" if result.safe else "\033[91m"
        verdict = f"{verdict_color if use_color else ''}{result.summary()}{RESET if use_color else ''}"
        print(f"\n  Verdict: {verdict}")

        if not result.safe:
            exit_code = max(exit_code, 1)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
