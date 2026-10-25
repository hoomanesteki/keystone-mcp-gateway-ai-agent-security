from importlib.metadata import version

import pytest

import keystone


@pytest.mark.phase(0)
def test_version_exposed() -> None:
    assert keystone.__version__ == "1.0.1"
    assert version("keystone") == keystone.__version__
