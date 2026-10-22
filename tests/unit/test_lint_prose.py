from pathlib import Path

import lint_prose
import pytest

ROOT = Path(__file__).resolve().parents[2]
EM_DASH = chr(0x2014)


def write(root: Path, name: str, text: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def findings(root: Path) -> set[tuple[str, int, str]]:
    return set(lint_prose.lint(root))


@pytest.mark.phase(0)
def test_flags_banned_words(tmp_path: Path) -> None:
    write(tmp_path, "README.md", "Fine line.\nWe leverage a seamless, robust design.\n")
    write(tmp_path, "CONTRIBUTING.md", "Furthermore, read the plan.\n")
    write(tmp_path, "docs/runbook.md", "It's worth noting that we dive into logs.\n")
    write(tmp_path, "site/index.html", "<p>Unlock the cutting-edge, state-of-the-art tool.</p>\n")

    result = findings(tmp_path)
    labels = {(path, message.split('"')[1]) for path, _, message in result}

    assert ("README.md", "leverage") in labels
    assert ("README.md", "seamless") in labels
    assert ("README.md", "robust") in labels
    assert ("CONTRIBUTING.md", "Furthermore,") in labels
    assert ("docs/runbook.md", "it's worth noting") in labels
    assert ("docs/runbook.md", "dive into") in labels
    assert {"unlock", "cutting-edge", "state-of-the-art"} <= {
        label for path, label in labels if path == "site/index.html"
    }
    assert all(number == 2 for path, number, _ in result if path == "README.md")


@pytest.mark.phase(0)
def test_banned_words_are_matched_as_words(tmp_path: Path) -> None:
    write(tmp_path, "README.md", "Leveraged ratios, robustness checks, unlocking later.\n")
    write(tmp_path, "docs/a.md", "The lever, a lock, an elevation, the ensemble.\n")

    flagged = {(path, message.split('"')[1]) for path, _, message in findings(tmp_path)}

    assert flagged == {("README.md", "leverage"), ("README.md", "robust"), ("README.md", "unlock")}


@pytest.mark.phase(0)
def test_plan_may_quote_the_banned_list_but_not_use_em_dashes(tmp_path: Path) -> None:
    write(tmp_path, "docs/PLAN.md", f"Banned: leverage, seamless.\nA {EM_DASH} B\n")

    result = findings(tmp_path)

    assert [(path, number) for path, number, _ in result] == [("docs/PLAN.md", 2)]
    assert "em dash" in next(iter(result))[2]


@pytest.mark.phase(0)
def test_em_dash_is_flagged_in_any_text_file_and_binaries_are_skipped(tmp_path: Path) -> None:
    write(tmp_path, "src/module.py", f"# a {EM_DASH} b\n")
    write(tmp_path, "notes/outside.txt", f"x {EM_DASH} y\n")
    (tmp_path / "image.bin").write_bytes(b"\0\0" + EM_DASH.encode())

    flagged = {path for path, _, _ in findings(tmp_path)}

    assert flagged == {"src/module.py", "notes/outside.txt"}


@pytest.mark.phase(0)
def test_main_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(tmp_path, "README.md", "Plain words.\n")
    assert lint_prose.main(["--root", str(tmp_path)]) == 0

    write(tmp_path, "README.md", "A seamless thing.\n")
    assert lint_prose.main(["--root", str(tmp_path)]) == 1
    assert 'README.md:1: banned phrase "seamless"' in capsys.readouterr().out


@pytest.mark.phase(0)
def test_this_repository_is_clean() -> None:
    assert lint_prose.lint(ROOT) == []
