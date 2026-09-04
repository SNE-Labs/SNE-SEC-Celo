"""Append-only SQLite store for completed reference Reviews."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from .codec import review_from_json, review_to_json
from .domain import CompletedReview
from .errors import ReviewAlreadyExists, ReviewNotFound


class SQLiteReviewStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path.resolve()

    def initialize(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection, connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS completed_reviews (
                    review_id TEXT PRIMARY KEY NOT NULL,
                    target_origin TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    result_digest TEXT UNIQUE NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_completed_reviews_target
                    ON completed_reviews(target_origin, completed_at);
                CREATE TRIGGER IF NOT EXISTS completed_reviews_no_update
                    BEFORE UPDATE ON completed_reviews
                    BEGIN SELECT RAISE(ABORT, 'completed Reviews are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS completed_reviews_no_delete
                    BEFORE DELETE ON completed_reviews
                    BEGIN SELECT RAISE(ABORT, 'completed Reviews are append-only'); END;
                """
            )

    def add(self, review: CompletedReview) -> None:
        payload = review_to_json(review)
        try:
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    """
                    INSERT INTO completed_reviews (
                        review_id, target_origin, provider_id, completed_at, result_digest, payload
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        review.review_id,
                        review.target_origin,
                        review.provider_id,
                        review.completed_at.isoformat(),
                        review.result_digest,
                        payload,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ReviewAlreadyExists("completed Review identity or digest already exists") from exc

    def get(self, review_id: str) -> CompletedReview:
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT payload FROM completed_reviews WHERE review_id = ?", (review_id,)
            ).fetchone()
        if row is None:
            raise ReviewNotFound(f"Review does not exist: {review_id}")
        return review_from_json(str(row[0]))

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection
