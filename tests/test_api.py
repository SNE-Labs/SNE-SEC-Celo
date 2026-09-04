from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from httpx import ASGITransport, AsyncClient

from sne_sec_celo.api import create_app


class ApiTests(unittest.IsolatedAsyncioTestCase):
    async def test_health_declares_standalone_reference_provider(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            transport = ASGITransport(
                app=create_app(database_path=Path(directory) / "reviews.sqlite3")
            )
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.get("/healthz")
            self.assertEqual(response.status_code, 200)
            self.assertFalse(response.json()["private_provider_required"])

    async def test_private_target_is_rejected_before_transport(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            transport = ASGITransport(
                app=create_app(database_path=Path(directory) / "reviews.sqlite3")
            )
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/v1/reference/reviews", json={"target": "localhost"}
                )
            self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
