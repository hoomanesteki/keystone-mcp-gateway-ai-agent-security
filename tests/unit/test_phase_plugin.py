import re
from pathlib import Path

import pytest

CONFTEST = Path(__file__).resolve().parents[1] / "conftest.py"


@pytest.fixture
def plugin_project(pytester: pytest.Pytester) -> pytest.Pytester:
    # Reuse the real conftest so the test covers the plugin that the suite ships.
    source = re.sub(r"^pytest_plugins = .*\n", "", CONFTEST.read_text(), flags=re.MULTILINE)
    pytester.makeconftest(source)
    return pytester


@pytest.mark.phase(0)
def test_missing_marker_is_error(plugin_project: pytest.Pytester) -> None:
    plugin_project.makepyfile(
        """
        def test_unmarked():
            assert True
        """
    )
    result = plugin_project.runpytest_subprocess()
    assert result.ret != 0
    result.stderr.fnmatch_lines(["*test_unmarked*is missing @pytest.mark.phase(n)*"])
    assert "1 passed" not in result.stdout.str()


@pytest.mark.phase(0)
def test_later_phase_skipped(plugin_project: pytest.Pytester) -> None:
    plugin_project.makepyfile(
        """
        import pytest

        @pytest.mark.phase(0)
        def test_now():
            assert True

        @pytest.mark.phase(1)
        def test_later():
            raise AssertionError("must not run")
        """
    )
    result = plugin_project.runpytest_subprocess("--phase", "0", "-rs")
    result.assert_outcomes(passed=1, skipped=1)
    result.stdout.fnmatch_lines(["*introduced in phase 1*"])


@pytest.mark.phase(0)
def test_all_phases_run_by_default(plugin_project: pytest.Pytester) -> None:
    plugin_project.makepyfile(
        """
        import pytest

        @pytest.mark.phase(7)
        def test_later():
            assert True
        """
    )
    plugin_project.runpytest_subprocess().assert_outcomes(passed=1)
