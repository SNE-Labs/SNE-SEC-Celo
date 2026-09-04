"""Command-line interface for clean-clone operation and witnesses."""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Sequence
from pathlib import Path

from .canonical import canonical_json
from .errors import ProtocolError
from .provider import ReferenceAssessmentProvider
from .service import ReviewService
from .store import SQLiteReviewStore


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sne-sec-celo")
    parser.add_argument(
        "--database", type=Path, default=Path(".sne-sec-celo/reviews.sqlite3")
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    review = subcommands.add_parser("review", help="create an immutable reference Review")
    review.add_argument("target")
    review.add_argument("--output", type=Path)
    show = subcommands.add_parser("show", help="retrieve a stored Review")
    show.add_argument("review_id")
    diff = subcommands.add_parser("diff", help="compare two stored Reviews")
    diff.add_argument("previous_review_id")
    diff.add_argument("current_review_id")
    subcommands.add_parser("serve", help="run the public HTTP API")
    return parser


def _service(database: Path) -> ReviewService:
    store = SQLiteReviewStore(database)
    store.initialize()
    return ReviewService(ReferenceAssessmentProvider(), store)


async def _review(args: argparse.Namespace) -> int:
    review = await _service(args.database).create_review(str(args.target))
    payload = canonical_json(review)
    output = args.output
    if isinstance(output, Path):
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "review_id": review.review_id,
                "target_origin": review.target_origin,
                "score": review.score,
                "findings": len(review.findings),
                "result_digest": review.result_digest,
                "output": str(output.resolve()) if isinstance(output, Path) else None,
            },
            sort_keys=True,
        )
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "review":
            return asyncio.run(_review(args))
        if args.command == "show":
            print(canonical_json(_service(args.database).get_review(str(args.review_id))))
            return 0
        if args.command == "diff":
            print(
                canonical_json(
                    _service(args.database).compare(
                        str(args.previous_review_id), str(args.current_review_id)
                    )
                )
            )
            return 0
        if args.command == "serve":
            from .api import run as run_api

            run_api()
            return 0
    except ProtocolError as exc:
        print(json.dumps({"error": type(exc).__name__, "detail": str(exc)}, sort_keys=True))
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
