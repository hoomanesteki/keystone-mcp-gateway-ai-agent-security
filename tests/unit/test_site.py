"""The project page in site/: its numbers are measured, its links resolve, its prose is clean."""

import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlparse

import lint_prose
import pytest

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "site"
INDEX = SITE / "index.html"
REPO_URL = "https://github.com/hoomanesteki/keystone-mcp-gateway-ai-agent-security"
BLOB = REPO_URL + "/blob/main/"
EM_DASH = chr(0x2014)

# Numbers that are not measurements. Each one says where it comes from.
STRUCTURAL = {
    "5",  # "5 minutes": the time the page promises for the demo
    "0006",
    "0009",
    "0010",
    "0018",  # ADR numbers, checked against docs/adr below
    "0.88",  # the scan score of the poisoned email, docs/progress.md KS-701 and the demo script
    "1.0",  # the right end of the axis of the recall chart, a scale and not a measurement
    "1",
    "2",
    "3",
    "4",
    "6",
    "7",
    "8",
    "9",
    "10",
    "11",  # section and step numbers
    "5173",
    "8180",  # console and Keycloak ports, docs/runbook.md
}


class Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.text: list[str] = []
        self.links: list[str] = []
        self.assets: list[str] = []
        self.ids: set[str] = set()
        self.skip = 0
        self.alts_missing = 0
        self.svgs = 0
        self.svg_titled = 0
        self.landmarks: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: v or "" for k, v in attrs}
        if "id" in a:
            self.ids.add(a["id"])
        if tag in ("style", "script"):
            self.skip += 1
        if tag == "a" and "href" in a:
            self.links.append(a["href"])
        if tag in ("img", "script", "source") and a.get("src"):
            self.assets.append(a["src"])
        if tag == "link" and a.get("href") and not a["href"].startswith("data:"):
            self.assets.append(a["href"])
        if tag == "img" and "alt" not in a:
            self.alts_missing += 1
        if tag == "svg":
            self.svgs += 1
            if a.get("role") == "img" and a.get("aria-labelledby"):
                self.svg_titled += 1
        if tag in ("main", "header", "footer", "nav"):
            self.landmarks.add(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag in ("style", "script"):
            self.skip -= 1

    def handle_data(self, data: str) -> None:
        if not self.skip:
            self.text.append(data)


def parse() -> Page:
    page = Page()
    page.feed(INDEX.read_text(encoding="utf-8"))
    return page


def corpus() -> str:
    """docs/results.md writes every number from the files in eval/results. The raw files hold
    per-call latencies, so a made-up number could match one by chance. Only the report counts."""
    return (ROOT / "docs" / "results.md").read_text(encoding="utf-8")


@pytest.mark.phase(9)
def test_every_number_is_measured() -> None:
    text = " ".join(parse().text)
    source = corpus()
    missing = []
    for token in sorted(set(re.findall(r"(?<![\w.\-])\d+(?:\.\d+)?(?![\w])", text))):
        if token in STRUCTURAL:
            continue
        if not re.search(r"(?<![\d.])" + re.escape(token) + r"(?!\d)", source):
            missing.append(token)
    assert not missing, f"numbers on the page that no results file has: {missing}"


@pytest.mark.phase(9)
def test_structural_numbers_are_real() -> None:
    progress = (ROOT / "docs" / "progress.md").read_text(encoding="utf-8")
    assert "0.88" in progress
    for adr in ("0006-cedar", "0009-audit-chain", "0010-approvals", "0018-untrusted-then-external"):
        assert (ROOT / "docs" / "adr" / f"{adr}.md").exists()
    runbook = (ROOT / "docs" / "runbook.md").read_text(encoding="utf-8")
    assert "5173" in runbook and "8180" in runbook


@pytest.mark.phase(9)
def test_links_and_assets_resolve() -> None:
    page = parse()
    assert page.links
    for href in page.links:
        if href.startswith("#"):
            assert href[1:] in page.ids, f"no element with id {href[1:]}"
        elif href.startswith(BLOB):
            rel = unquote(
                urlparse(href).path.removeprefix(
                    "/hoomanesteki/keystone-mcp-gateway-ai-agent-security/blob/main/"
                )
            )
            assert (ROOT / rel).exists(), f"{href} points at a file that is not in the repo"
            fragment = urlparse(href).fragment
            if fragment:
                body = (ROOT / rel).read_text(encoding="utf-8")
                slugs = {
                    re.sub(r"[^a-z0-9 \-]", "", h.lower()).strip().replace(" ", "-")
                    for h in re.findall(r"^#+\s+(.+)$", body, flags=re.M)
                }
                assert fragment in slugs, f"{href}: no heading {fragment}"
        elif href.startswith(("https://", "http://")):
            assert (
                href == REPO_URL
                or href.startswith(REPO_URL)
                or href.startswith("https://docs.astral.sh/")
            )
        else:
            assert (SITE / href).exists(), f"{href} does not exist in site/"
    for src in page.assets:
        assert not src.startswith(("/", "http")), f"asset path {src} is not relative"
        assert (SITE / src).exists(), f"asset {src} does not exist"
    assert (SITE / ".nojekyll").exists()


@pytest.mark.phase(9)
def test_page_has_no_em_dash_and_passes_the_prose_lint() -> None:
    assert EM_DASH not in INDEX.read_text(encoding="utf-8")
    assert not [f for f in lint_prose.lint(ROOT) if f[0].startswith("site/")]
    assert "!" not in " ".join(parse().text)


@pytest.mark.phase(9)
def test_page_structure_and_accessibility() -> None:
    page = parse()
    html = INDEX.read_text(encoding="utf-8")
    assert {"main", "header", "footer", "nav"} <= page.landmarks
    assert 'class="skip"' in html and 'lang="en"' in html
    assert page.svgs == page.svg_titled and page.svgs >= 6
    assert page.alts_missing == 0
    assert "prefers-color-scheme" in html and "viewport" in html
    assert not re.search(r"<script[^>]+src=", html), "the page loads no external script"
    for section in (
        "problem",
        "design",
        "pipeline",
        "rule-of-two",
        "attack",
        "results",
        "limits",
        "run",
        "decisions",
    ):
        assert f'id="{section}"' in html
    assert "not run: needs an API key" in " ".join(page.text)


@pytest.mark.phase(9)
def test_pages_workflow() -> None:
    import yaml

    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "pages.yml").read_text(encoding="utf-8"))
    on = wf.get("on", wf.get(True))
    assert on["push"]["branches"] == ["main"]
    assert "site/**" in on["push"]["paths"] and "workflow_dispatch" in on
    assert wf["permissions"] == {"contents": "read", "pages": "write", "id-token": "write"}
    assert wf["concurrency"]["group"] == "pages"
    steps = " ".join(s.get("uses", "") for s in wf["jobs"]["deploy"]["steps"])
    for action in ("configure-pages", "upload-pages-artifact", "deploy-pages"):
        assert action in steps
