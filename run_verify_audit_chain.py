"""Command-line entry point for verifying a hash-chained audit log's integrity.

Walks a JSONL audit log written by `reasoning.audit_log.AuditLog` and
reports whether its hash chain is intact end to end, or the index (in
append order) of the first entry where it breaks and which check failed
there. See `reasoning/audit_log.py`'s module docstring for what the chain
actually protects against, and `docs/adr/0007-tamper-evident-audit-log.md`
for the design.

    python run_verify_audit_chain.py --log-path service_audit.jsonl
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from reasoning.audit_chain import verify_chain
from reasoning.audit_log import AuditLog

DEFAULT_LOG_PATH = Path("service_audit.jsonl")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    """Parses command-line arguments.

    Args:
        argv: Argument list, excluding the program name.

    Returns:
        The parsed arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--log-path", type=Path, default=DEFAULT_LOG_PATH,
        help="path to the JSONL audit log to verify",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Verifies the audit log's hash chain and prints the result.

    Args:
        argv: Argument list, excluding the program name. Defaults to sys.argv.

    Returns:
        A process exit code: 0 if the chain is intact, 1 if it is broken or
        the log file does not exist.
    """
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    if not args.log_path.exists():
        print(f"no audit log at {args.log_path}", file=sys.stderr)
        return 1

    log = AuditLog(args.log_path)
    result = verify_chain(log.read_entries())

    if result.intact:
        print(f"chain intact: {result.total_records} record(s), genesis to head, no break found")
        return 0

    print(
        f"chain broken at index {result.first_break_index} of {result.total_records}: "
        f"{result.broken_field} mismatch",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
