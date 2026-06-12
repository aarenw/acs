"""CLI entry point: export | check | apply | run."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from acs.acs_api import build_summary_tsv, export_and_summarize
from acs.apply import apply_results
from acs.purge_exceptions import purge_fp_defer_exceptions
from acs.config import Settings, load_default_env, load_env_file
from acs.rhsda_check import check_summary
from acs.common import timestamp_utc

log = logging.getLogger(__name__)


def _resolve_summary(report: Path, settings: Settings) -> Path:
    if report.name.endswith(".summary.tsv"):
        return report
    if report.suffix == ".jsonl" or report.name.endswith(".jsonl"):
        summary = Path(str(report).replace(".jsonl", ".summary.tsv"))
        build_summary_tsv(settings, report, summary)
        return summary
    raise SystemExit(f"unsupported report format: {report} (expected .summary.tsv or .jsonl)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="platform-fp-check",
        description="Platform CVE exception automation (export -> RHSDA check -> apply)",
    )
    parser.add_argument("--env", dest="env_file", help="Load environment from FILE")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("export", help="Export platform component vulnerabilities from ACS")

    p_check = sub.add_parser("check", help="Run RHSDA verification on summary TSV")
    p_check.add_argument("--report", required=True, help="Path to summary TSV or JSONL")

    p_apply = sub.add_parser("apply", help="Create and approve FP/deferral exceptions in ACS")
    p_apply.add_argument("--results", required=True, help="Path to rhsda-check JSON")

    sub.add_parser(
        "purge-exceptions",
        help="Cancel approved or delete pending false-positive/deferral exceptions",
    )

    sub.add_parser("run", help="export -> check -> apply (full pipeline)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.env_file:
        load_env_file(Path(args.env_file))
    else:
        loaded = load_default_env()
        if loaded:
            log.info("loaded env from %s", loaded)

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    settings = Settings.from_env()

    if args.command == "export":
        jsonl, summary = export_and_summarize(settings)
        print(jsonl)
        print(summary)
        return 0

    if args.command == "check":
        summary = _resolve_summary(Path(args.report), settings)
        out = settings.results_dir / f"rhsda-check-{timestamp_utc()}.json"
        path = check_summary(settings, summary, out)
        print(path)
        return 0

    if args.command == "apply":
        out = settings.results_dir / f"exception-actions-{timestamp_utc()}.json"
        path = apply_results(settings, Path(args.results), out)
        print(path)
        return 0

    if args.command == "purge-exceptions":
        out = settings.results_dir / f"exception-purge-{timestamp_utc()}.json"
        path = purge_fp_defer_exceptions(settings, out)
        print(path)
        return 0

    if args.command == "run":
        jsonl, summary = export_and_summarize(settings)
        log.info("export complete: %s", jsonl)
        results = settings.results_dir / f"rhsda-check-{timestamp_utc()}.json"
        check_summary(settings, summary, results)
        actions = settings.results_dir / f"exception-actions-{timestamp_utc()}.json"
        apply_results(settings, results, actions)
        log.info("pipeline complete")
        print(f"report_jsonl={jsonl}")
        print(f"report_summary={summary}")
        print(f"rhsda_results={results}")
        print(f"exception_actions={actions}")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
