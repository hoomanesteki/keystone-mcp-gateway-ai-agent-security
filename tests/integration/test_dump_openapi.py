"""KS-605: the schema the console's types come from is the one the gateway serves."""

import dump_openapi
import httpx2
import pytest

from tests.fixtures.keystone import KeystoneApp

pytestmark = [pytest.mark.phase(6), pytest.mark.services]


async def test_the_dumped_schema_is_the_one_the_gateway_serves(keystone_app: KeystoneApp) -> None:
    served = httpx2.get(f"{keystone_app.base}/admin/api/v1/openapi.json", timeout=10).json()

    assert dump_openapi.admin_schema() == served
