"""Run one real-network reference Review and emit only non-sensitive witness metadata."""

from __future__ import annotations

import argparse
import asyncio
import json
import tempfile
from pathlib import Path

from sne_sec_celo.provider import ReferenceAssessmentProvider
from sne_sec_celo.service import ReviewService
from sne_sec_celo.store import SQLiteReviewStore


async def witness(target: str) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="sne-sec-celo-witness-") as directory:
        store = SQLiteReviewStore(Path(directory) / "reviews.sqlite3")
        store.initialize()
        service = ReviewService(ReferenceAssessmentProvider(), store)
        review = await service.create_review(target)
        restored = service.get_review(review.review_id)
        return {
            "status": "PASS",
            "target_origin": restored.target_origin,
            "provider_id": restored.provider_id,
            "observations": len(restored.observations),
            "evidence": len(restored.evidence),
            "evaluations": len(restored.evaluations),
            "findings": len(restored.findings),
            "score": restored.score,
            "digest_reproduced": restored.result_digest == review.result_digest,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    args = parser.parse_args()
    print(json.dumps(asyncio.run(witness(args.target)), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
