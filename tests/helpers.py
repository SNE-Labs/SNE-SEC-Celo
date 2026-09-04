from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

from sne_sec_celo.provider import ReferenceAssessmentProvider
from sne_sec_celo.targets import AdmittedResolution, CollectionURL
from sne_sec_celo.transport import HttpExchange


class SequenceClock:
    def __init__(self) -> None:
        self._current = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        value = self._current
        self._current += timedelta(milliseconds=1)
        return value


class SequenceIds:
    def __init__(self) -> None:
        self._next = 0

    def __call__(self, prefix: str) -> str:
        self._next += 1
        return f"{prefix}_{self._next:04d}"


class FakeResolver:
    def __init__(self, answers: tuple[str, ...] = ("93.184.216.34",)) -> None:
        self.answers = answers
        self.targets: list[CollectionURL] = []

    async def resolve(self, target: CollectionURL) -> tuple[str, ...]:
        self.targets.append(target)
        return self.answers


class FakeTransport:
    def __init__(self, exchanges: tuple[HttpExchange, ...]) -> None:
        self._exchanges: Iterator[HttpExchange] = iter(exchanges)
        self.resolutions: list[AdmittedResolution] = []

    async def fetch(self, resolution: AdmittedResolution) -> HttpExchange:
        self.resolutions.append(resolution)
        return next(self._exchanges)


def exchange(
    status: int = 200, headers: tuple[tuple[str, str], ...] = ()
) -> HttpExchange:
    return HttpExchange(
        status_code=status,
        headers=headers,
        selected_address="93.184.216.34",
        connected_peer="93.184.216.34",
        receipt_digest=f"sha256:{status:064x}",
    )


def provider(*exchanges: HttpExchange) -> ReferenceAssessmentProvider:
    return ReferenceAssessmentProvider(
        resolver=FakeResolver(),
        transport=FakeTransport(tuple(exchanges)),
        clock=SequenceClock(),
        id_factory=SequenceIds(),
    )
