"""Public HTTP API for the executable reference provider."""

from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.types import Scope
from x402.http.middleware.fastapi import PaymentMiddlewareASGI

from .agent import AGENT_SVG, AgentSettings, build_capabilities, build_registration_file
from .canonical import canonical_json
from .errors import (
    CollectionFailed,
    InvariantViolation,
    ReviewAlreadyExists,
    ReviewNotFound,
    TargetRejected,
)
from .payment_store import SQLitePaymentStore
from .projections import review_diff_preview, review_preview
from .provider import AssessmentProvider, ReferenceAssessmentProvider
from .service import ReviewService
from .store import SQLiteReviewStore
from .x402_runtime import (
    X402Runtime,
    X402Settings,
    build_commercial_policy,
    build_x402_runtime,
)


class CreateReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str = Field(min_length=1, max_length=4096)


class ReviewDiffRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    previous_review_id: str = Field(min_length=1, max_length=128)
    current_review_id: str = Field(min_length=1, max_length=128)


class CyberIntelligenceStaticFiles(StaticFiles):
    """Serve the browser surface with a closed, same-origin security policy."""

    async def get_response(self, path: str, scope: Scope) -> Response:
        response = await super().get_response(path, scope)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        return response


def _payload(value: object) -> object:
    return json.loads(canonical_json(value))


def create_app(
    *,
    database_path: Path | None = None,
    agent_settings: AgentSettings | None = None,
    x402_settings: X402Settings | None = None,
    x402_runtime: X402Runtime | None = None,
    assessment_provider: AssessmentProvider | None = None,
    public_example_review_id: str | None = None,
    web_root: Path | None = None,
) -> FastAPI:
    path = database_path or Path(
        os.environ.get("SNE_SEC_CELO_DATABASE", ".sne-sec-celo/reviews.sqlite3")
    )
    store = SQLiteReviewStore(path)
    store.initialize()
    service = ReviewService(assessment_provider or ReferenceAssessmentProvider(), store)
    settings = agent_settings or AgentSettings.from_environment()
    payment_settings = x402_settings or X402Settings.from_environment(settings)
    example_review_id = public_example_review_id
    if example_review_id is None:
        example_review_id = os.environ.get("SNE_SEC_CELO_PUBLIC_EXAMPLE_REVIEW_ID")
    if example_review_id is not None:
        example_review_id = example_review_id.strip()
        if (
            not example_review_id
            or len(example_review_id) > 128
            or "/" in example_review_id
            or "\\" in example_review_id
        ):
            raise InvariantViolation("public example Review ID is malformed")
    if payment_settings.enabled != settings.x402_enabled:
        raise InvariantViolation("agent and x402 enabled states must agree")
    app = FastAPI(
        title="SNE-SEC Celo Agent",
        version="1.0.0",
        description="Open agent and evidence protocol with an executable reference provider.",
    )
    app.state.review_service = service
    payment_runtime: X402Runtime | None = None
    if payment_settings.enabled:
        payment_store = SQLitePaymentStore(path)
        payment_store.initialize()
        payment_runtime = x402_runtime or build_x402_runtime(
            settings=payment_settings,
            store=payment_store,
        )
        if payment_runtime.store.database_path != path.resolve():
            raise InvariantViolation("x402 ledger must share the configured durable database")
        app.state.payment_store = payment_runtime.store

    @app.get("/.well-known/agent.json")
    @app.get("/.well-known/agent-registration.json", include_in_schema=False)
    @app.get("/agent-registration.json", include_in_schema=False)
    def agent_registration() -> dict[str, object]:
        return build_registration_file(settings)

    @app.get("/.well-known/sne-sec-capabilities.json")
    def capabilities() -> dict[str, object]:
        return build_capabilities(settings)

    @app.get("/.well-known/sne-sec-commerce.json")
    def commercial_policy() -> dict[str, object]:
        return build_commercial_policy(payment_settings, example_review_id)

    @app.get("/assets/sne-sec-celo-agent.svg", include_in_schema=False)
    def agent_image() -> Response:
        return Response(content=AGENT_SVG, media_type="image/svg+xml")

    @app.get("/healthz")
    def health() -> dict[str, object]:
        return {
            "status": "ok",
            "provider": "sne-sec-celo-reference",
            "private_provider_required": False,
            "erc8004_registered": settings.agent_id is not None,
            "x402_enabled": settings.x402_enabled,
            "x402_settlement_admission": (
                "INDEPENDENT_CELO_CONFIRMATIONS" if settings.x402_enabled else None
            ),
        }

    @app.post("/v1/reference/reviews", status_code=201)
    async def create_review(request: CreateReviewRequest) -> object:
        try:
            return _payload(review_preview(await service.create_review(request.target)))
        except TargetRejected as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except CollectionFailed as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        except ReviewAlreadyExists as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/v1/reviews/{review_id}")
    def get_review(review_id: str) -> object:
        try:
            return _payload(review_preview(service.get_review(review_id)))
        except ReviewNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/v1/reference/example-review")
    def get_public_example_review() -> object:
        if example_review_id is None:
            raise HTTPException(status_code=404, detail="public example Review is not configured")
        try:
            return _payload(service.get_review(example_review_id))
        except ReviewNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    if payment_runtime is not None:

        @app.get("/v1/x402/reviews/{review_id}")
        def get_paid_review(review_id: str) -> object:
            try:
                return _payload(service.get_review(review_id))
            except ReviewNotFound as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc

        @app.get(
            "/v1/x402/review-diffs/{previous_review_id}/{current_review_id}"
        )
        def compare_paid_reviews(
            previous_review_id: str, current_review_id: str
        ) -> object:
            try:
                return _payload(service.compare(previous_review_id, current_review_id))
            except ReviewNotFound as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/v1/review-diffs")
    def compare_reviews(request: ReviewDiffRequest) -> object:
        try:
            return _payload(
                review_diff_preview(
                    service.compare(request.previous_review_id, request.current_review_id)
                )
            )
        except ReviewNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    if payment_runtime is not None:
        app.add_middleware(
            PaymentMiddlewareASGI,
            routes=payment_runtime.routes,
            server=payment_runtime.server,
        )
    configured_web_root = web_root
    if configured_web_root is None:
        configured = os.environ.get("SNE_SEC_CELO_WEB_ROOT")
        configured_web_root = Path(configured) if configured else None
    if configured_web_root is not None:
        resolved_web_root = configured_web_root.resolve()
        if not (resolved_web_root / "index.html").is_file():
            raise InvariantViolation("configured web root has no index.html")
        app.mount(
            "/",
            CyberIntelligenceStaticFiles(directory=resolved_web_root, html=True),
            name="sne-sec-cyber-intelligence",
        )
    return app


app = create_app()


def run() -> None:
    import uvicorn

    uvicorn.run("sne_sec_celo.api:app", host="0.0.0.0", port=8000)
