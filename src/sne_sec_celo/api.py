"""Public HTTP API for the executable reference provider."""

from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .canonical import canonical_json
from .errors import CollectionFailed, ReviewAlreadyExists, ReviewNotFound, TargetRejected
from .provider import ReferenceAssessmentProvider
from .service import ReviewService
from .store import SQLiteReviewStore


class CreateReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str = Field(min_length=1, max_length=4096)


class ReviewDiffRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    previous_review_id: str = Field(min_length=1, max_length=128)
    current_review_id: str = Field(min_length=1, max_length=128)


def _payload(value: object) -> object:
    return json.loads(canonical_json(value))


def create_app(*, database_path: Path | None = None) -> FastAPI:
    path = database_path or Path(
        os.environ.get("SNE_SEC_CELO_DATABASE", ".sne-sec-celo/reviews.sqlite3")
    )
    store = SQLiteReviewStore(path)
    store.initialize()
    service = ReviewService(ReferenceAssessmentProvider(), store)
    app = FastAPI(
        title="SNE-SEC Celo Agent",
        version="1.0.0",
        description="Open agent and evidence protocol with an executable reference provider.",
    )
    app.state.review_service = service

    @app.get("/healthz")
    def health() -> dict[str, object]:
        return {
            "status": "ok",
            "provider": "sne-sec-celo-reference",
            "private_provider_required": False,
        }

    @app.post("/v1/reference/reviews", status_code=201)
    async def create_review(request: CreateReviewRequest) -> object:
        try:
            return _payload(await service.create_review(request.target))
        except TargetRejected as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except CollectionFailed as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        except ReviewAlreadyExists as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/v1/reviews/{review_id}")
    def get_review(review_id: str) -> object:
        try:
            return _payload(service.get_review(review_id))
        except ReviewNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/v1/review-diffs")
    def compare_reviews(request: ReviewDiffRequest) -> object:
        try:
            return _payload(
                service.compare(request.previous_review_id, request.current_review_id)
            )
        except ReviewNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    return app


app = create_app()


def run() -> None:
    import uvicorn

    uvicorn.run("sne_sec_celo.api:app", host="0.0.0.0", port=8000)
