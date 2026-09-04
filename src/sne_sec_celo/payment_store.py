"""Append-only SQLite ledger for x402 intent, claim, observation, and settlement."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any, cast

from .canonical import canonical_json, parse_utc
from .errors import InvariantViolation
from .payments import (
    CeloSettlementObservation,
    FacilitatorSettlementClaim,
    PaymentIntent,
    PaymentSettlement,
)


class SQLitePaymentStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path.resolve()

    def initialize(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection, connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS payment_intents (
                    intent_id TEXT PRIMARY KEY NOT NULL,
                    authorization_id TEXT UNIQUE NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS facilitator_settlement_claims (
                    claim_id TEXT PRIMARY KEY NOT NULL,
                    intent_id TEXT NOT NULL REFERENCES payment_intents(intent_id),
                    transaction_hash TEXT UNIQUE NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS celo_settlement_observations (
                    observation_id TEXT PRIMARY KEY NOT NULL,
                    intent_id TEXT NOT NULL REFERENCES payment_intents(intent_id),
                    authorization_id TEXT UNIQUE NOT NULL,
                    external_event_id TEXT UNIQUE NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS payment_settlements (
                    settlement_id TEXT PRIMARY KEY NOT NULL,
                    intent_id TEXT UNIQUE NOT NULL REFERENCES payment_intents(intent_id),
                    claim_id TEXT UNIQUE NOT NULL
                        REFERENCES facilitator_settlement_claims(claim_id),
                    observation_id TEXT UNIQUE NOT NULL
                        REFERENCES celo_settlement_observations(observation_id),
                    external_event_id TEXT UNIQUE NOT NULL,
                    payload TEXT NOT NULL
                );

                CREATE TRIGGER IF NOT EXISTS payment_intents_no_update
                    BEFORE UPDATE ON payment_intents
                    BEGIN SELECT RAISE(ABORT, 'payment intents are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS payment_intents_no_delete
                    BEFORE DELETE ON payment_intents
                    BEGIN SELECT RAISE(ABORT, 'payment intents are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS facilitator_claims_no_update
                    BEFORE UPDATE ON facilitator_settlement_claims
                    BEGIN SELECT RAISE(ABORT, 'facilitator claims are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS facilitator_claims_no_delete
                    BEFORE DELETE ON facilitator_settlement_claims
                    BEGIN SELECT RAISE(ABORT, 'facilitator claims are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS celo_observations_no_update
                    BEFORE UPDATE ON celo_settlement_observations
                    BEGIN SELECT RAISE(ABORT, 'Celo observations are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS celo_observations_no_delete
                    BEFORE DELETE ON celo_settlement_observations
                    BEGIN SELECT RAISE(ABORT, 'Celo observations are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS payment_settlements_no_update
                    BEFORE UPDATE ON payment_settlements
                    BEGIN SELECT RAISE(ABORT, 'payment settlements are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS payment_settlements_no_delete
                    BEFORE DELETE ON payment_settlements
                    BEGIN SELECT RAISE(ABORT, 'payment settlements are append-only'); END;
                """
            )

    def record_intent(self, intent: PaymentIntent) -> None:
        payload = canonical_json(intent)
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                """
                SELECT payload FROM payment_intents
                WHERE intent_id = ? OR authorization_id = ?
                """,
                (intent.intent_id, intent.authorization_id),
            ).fetchall()
            if rows:
                if len(rows) == 1 and _same_except_time(
                    str(rows[0][0]), payload, "created_at"
                ):
                    return
                raise InvariantViolation(
                    "payment authorization replay conflicts with durable intent"
                )
            connection.execute(
                """
                INSERT INTO payment_intents (intent_id, authorization_id, payload)
                VALUES (?, ?, ?)
                """,
                (intent.intent_id, intent.authorization_id, payload),
            )

    def get_intent_by_authorization(self, authorization_id: str) -> PaymentIntent:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT payload FROM payment_intents WHERE authorization_id = ?",
                (authorization_id,),
            ).fetchone()
        if row is None:
            raise InvariantViolation("durable payment intent does not exist")
        return _intent_from_json(str(row[0]))

    def record_claim(self, claim: FacilitatorSettlementClaim) -> None:
        payload = canonical_json(claim)
        with closing(self._connect()) as connection, connection:
            if (
                connection.execute(
                    "SELECT 1 FROM payment_intents WHERE intent_id = ?", (claim.intent_id,)
                ).fetchone()
                is None
            ):
                raise InvariantViolation("facilitator claim has no durable payment intent")
            rows = connection.execute(
                """
                SELECT payload FROM facilitator_settlement_claims
                WHERE claim_id = ? OR transaction_hash = ?
                """,
                (claim.claim_id, claim.transaction_hash),
            ).fetchall()
            if rows:
                if len(rows) == 1 and _same_except_time(
                    str(rows[0][0]), payload, "claimed_at"
                ):
                    return
                raise InvariantViolation("facilitator settlement claim conflicts with prior claim")
            connection.execute(
                """
                INSERT INTO facilitator_settlement_claims (
                    claim_id, intent_id, transaction_hash, payload
                ) VALUES (?, ?, ?, ?)
                """,
                (claim.claim_id, claim.intent_id, claim.transaction_hash, payload),
            )

    def claim_for_authorization(
        self, authorization_id: str
    ) -> FacilitatorSettlementClaim | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT c.payload
                FROM facilitator_settlement_claims AS c
                JOIN payment_intents AS i ON i.intent_id = c.intent_id
                WHERE i.authorization_id = ?
                """,
                (authorization_id,),
            ).fetchone()
        return None if row is None else _claim_from_json(str(row[0]))

    def admit_settlement(
        self,
        observation: CeloSettlementObservation,
        settlement: PaymentSettlement,
    ) -> None:
        if (
            observation.intent_id != settlement.intent_id
            or observation.observation_id != settlement.observation_id
            or observation.external_event_id != settlement.external_event_id
            or observation.authorization_id != settlement.authorization_id
        ):
            raise InvariantViolation("settlement does not bind its admitted Celo observation")
        observation_payload = canonical_json(observation)
        settlement_payload = canonical_json(settlement)
        with closing(self._connect()) as connection, connection:
            if (
                connection.execute(
                    """
                    SELECT 1 FROM facilitator_settlement_claims
                    WHERE claim_id = ? AND intent_id = ?
                    """,
                    (settlement.claim_id, settlement.intent_id),
                ).fetchone()
                is None
            ):
                raise InvariantViolation("settlement has no durable facilitator claim")
            self._insert_observation(connection, observation, observation_payload)
            self._insert_settlement(connection, settlement, settlement_payload)

    def settlement_for_transaction(self, transaction_hash: str) -> PaymentSettlement | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT s.payload
                FROM payment_settlements AS s
                JOIN facilitator_settlement_claims AS c ON c.claim_id = s.claim_id
                WHERE c.transaction_hash = ?
                """,
                (transaction_hash.lower(),),
            ).fetchone()
        return None if row is None else _settlement_from_json(str(row[0]))

    @staticmethod
    def _insert_observation(
        connection: sqlite3.Connection,
        observation: CeloSettlementObservation,
        payload: str,
    ) -> None:
        rows = connection.execute(
            """
            SELECT payload FROM celo_settlement_observations
            WHERE observation_id = ? OR authorization_id = ? OR external_event_id = ?
            """,
            (
                observation.observation_id,
                observation.authorization_id,
                observation.external_event_id,
            ),
        ).fetchall()
        if rows:
            if len(rows) == 1 and _same_except_time(
                str(rows[0][0]), payload, "observed_at"
            ):
                return
            raise InvariantViolation("Celo settlement observation is replayed or ambiguous")
        connection.execute(
            """
            INSERT INTO celo_settlement_observations (
                observation_id, intent_id, authorization_id, external_event_id, payload
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                observation.observation_id,
                observation.intent_id,
                observation.authorization_id,
                observation.external_event_id,
                payload,
            ),
        )

    @staticmethod
    def _insert_settlement(
        connection: sqlite3.Connection,
        settlement: PaymentSettlement,
        payload: str,
    ) -> None:
        rows = connection.execute(
            """
            SELECT payload FROM payment_settlements
            WHERE settlement_id = ? OR intent_id = ? OR claim_id = ?
                OR observation_id = ? OR external_event_id = ?
            """,
            (
                settlement.settlement_id,
                settlement.intent_id,
                settlement.claim_id,
                settlement.observation_id,
                settlement.external_event_id,
            ),
        ).fetchall()
        if rows:
            if len(rows) == 1 and _same_except_time(
                str(rows[0][0]), payload, "settled_at"
            ):
                return
            raise InvariantViolation("payment settlement is replayed or ambiguous")
        connection.execute(
            """
            INSERT INTO payment_settlements (
                settlement_id, intent_id, claim_id, observation_id, external_event_id, payload
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                settlement.settlement_id,
                settlement.intent_id,
                settlement.claim_id,
                settlement.observation_id,
                settlement.external_event_id,
                payload,
            ),
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection


def _object(value: str) -> dict[str, Any]:
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise InvariantViolation("stored payment record is malformed")
    return cast(dict[str, Any], parsed)


def _same_except_time(left: str, right: str, time_field: str) -> bool:
    left_value = _object(left)
    right_value = _object(right)
    left_value.pop(time_field, None)
    right_value.pop(time_field, None)
    return left_value == right_value


def _intent_from_json(value: str) -> PaymentIntent:
    item = _object(value)
    item["created_at"] = parse_utc(str(item["created_at"]))
    return PaymentIntent(**item)


def _settlement_from_json(value: str) -> PaymentSettlement:
    item = _object(value)
    item["settled_at"] = parse_utc(str(item["settled_at"]))
    return PaymentSettlement(**item)


def _claim_from_json(value: str) -> FacilitatorSettlementClaim:
    item = _object(value)
    item["claimed_at"] = parse_utc(str(item["claimed_at"]))
    return FacilitatorSettlementClaim(**item)
