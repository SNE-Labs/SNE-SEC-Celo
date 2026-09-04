"""Application service joining providers, immutable storage, and ReviewDiff."""

from __future__ import annotations

from .domain import CompletedReview, ReviewDiff, build_review_diff
from .provider import AssessmentProvider
from .store import SQLiteReviewStore


class ReviewService:
    def __init__(self, provider: AssessmentProvider, store: SQLiteReviewStore) -> None:
        self.provider = provider
        self.store = store

    async def create_review(self, target: str) -> CompletedReview:
        review = await self.provider.assess(target)
        self.store.add(review)
        return review

    def get_review(self, review_id: str) -> CompletedReview:
        return self.store.get(review_id)

    def compare(self, previous_review_id: str, current_review_id: str) -> ReviewDiff:
        return build_review_diff(
            self.store.get(previous_review_id), self.store.get(current_review_id)
        )
