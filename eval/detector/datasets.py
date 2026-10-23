"""The dataset of the detector evaluation: fixed, split by carrier and checked by hash (KS-707).

    python -m eval.detector.datasets build            # build it, downloading the public parts
    python -m eval.detector.datasets build --offline  # the synthetic parts only
    python -m eval.detector.datasets manifest         # write eval/detector/manifest.json

A sample is a text and a label (1 an injection, 0 not) of one of four kinds:

- `public`: a prompt of `deepset/prompt-injections` (Hugging Face), labelled by that dataset.
- `indirect`: a benign carrier (an email, a page or a file) with an attack from the templates of
  KS-708 put at its start, middle or end, with or without hidden Unicode. Label 1.
- `negative`: a carrier as it is. Label 0.
- `hard_negative`: harmless text that sounds like an instruction (`hard.py`). Label 0.

The carriers are the fixtures of the repository, documents generated from sentence banks
(`carriers.py`) and, when the download works, 60 articles of WikiText-2. Every choice that the
generators make comes from a hash of the sample's name, so a build is the same on every machine.
The split into `dev` and `test` is by carrier, from a hash too: a carrier, and every attack put in
it, is in one split. The thresholds are tuned on `dev`, and `test` is for the numbers that are
published.

`manifest.json` lists the sha256 of every sample's text. A build is checked against it, and a text
that differs is an error: a number must not be reported on data that changed under it. The public
parts are the parquet files of two Hugging Face datasets, downloaded at a pinned revision (the
files cannot change under that address) and read with pyarrow, from the extra `keystone[eval]`.
Their rows are cached in `eval/data/`, which is not committed, and are checked against the
manifest like everything else. The datasets server's JSON API was tried first and answers 429
after a few dozen requests, which a build of 60 articles cannot stay under. When the download is
not possible, or pyarrow is not installed, the build is the synthetic parts, and says so in
`Dataset.notes`; the report repeats it.

Nothing here puts the `ks-do` marker of the naive agent into a text (`examples/injections.py`):
a detector must not be measured on a text that still has one.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import time
from collections import Counter
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from eval.detector.carriers import Carrier, digest, pick, synthetic_carriers
from eval.detector.hard import hard_negatives
from examples.injections import TAG_BASE, Goal, Template, load, render, strip_markers

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
MANIFEST = HERE / "manifest.json"
DATA_DIR = REPO / "eval" / "data"

VERSION = 1
SEED = 20261023
DEV_PERCENT = 50
POSITIONS = ("start", "middle", "end")
# One attack in every four is hidden: half of those with zero-width characters between the letters
# of the words, and half written entirely in Unicode tag characters.
HIDDEN_ONE_IN = 4
ZERO_WIDTH = "​"
PER_CARRIER = 2

HUB = "https://huggingface.co/datasets"
ATTEMPTS = 4
TIMEOUT_S = 60.0

SYNTHETIC, PUBLIC_PART, WIKI_PART = "synthetic", "public", "wikitext"


@dataclass(frozen=True)
class Source:
    """A public dataset: where its files are at a pinned revision, and what its license is."""

    name: str
    revision: str
    license: str
    # split -> path of its parquet file in the repository
    files: Mapping[str, str]

    def url(self, split: str) -> str:
        return f"{HUB}/{self.name}/resolve/{self.revision}/{self.files[split]}"


PUBLIC = Source(
    "deepset/prompt-injections",
    "4f61ecb038e9c3fb77e21034b22511b523772cdd",
    "apache-2.0",
    {
        "train": "data/train-00000-of-00001-9564e8b05b4757ab.parquet",
        "test": "data/test-00000-of-00001-701d16158af87368.parquet",
    },
)
WIKITEXT = Source(
    "Salesforce/wikitext",
    "b08601e04326c79dfdd32d625aee71d232d685c3",
    "cc-by-sa-3.0 and gfdl",
    {"test": "wikitext-2-raw-v1/test-00000-of-00001.parquet"},
)
# WikiText-2's test split is 60 articles. Each becomes one carrier, cut to a length that its
# number picks, so that the pages are spread over the three length buckets.
WIKI_ARTICLES = 60
WIKI_LENGTHS = (1_200, 5_000, 16_000)


@dataclass(frozen=True)
class Sample:
    id: str
    text: str
    label: int
    kind: str
    carrier: str
    split: str
    part: str
    # What made the sample: the template, goal, position and hiding of an attack, or the carrier's
    # kind and source. A report groups by these.
    meta: Mapping[str, str] = field(default_factory=dict)

    @property
    def tokens(self) -> float:
        """Four characters make a token, as in docs/spikes/scanner.md. It names the bucket and
        is not a count of what a model would read."""
        return len(self.text) / 4


@dataclass(frozen=True)
class Dataset:
    samples: tuple[Sample, ...]
    # What is missing from the full build, in words for the report.
    notes: tuple[str, ...] = ()
    parts: Mapping[str, int] = field(default_factory=dict)

    def split(self, name: str) -> list[Sample]:
        return [s for s in self.samples if s.split == name]

    @property
    def complete(self) -> bool:
        return not self.notes


class DatasetChanged(RuntimeError):
    """A text is not the one the manifest names. The numbers of an evaluation must not be reported
    on data that changed under them."""


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def split_of(carrier: str) -> str:
    return "dev" if digest(f"{SEED}:split:{carrier}") % 100 < DEV_PERCENT else "test"


# -- the attacks put into the carriers


def to_tags(text: str) -> str:
    """The text in Unicode tag characters, which no editor draws. Characters with no tag stay."""
    return "".join(chr(TAG_BASE + ord(c)) if 0x20 <= ord(c) <= 0x7E else c for c in text)


def interleave(text: str) -> str:
    """The text with a zero-width space after every fourth letter of a word."""
    out: list[str] = []
    run = 0
    for char in text:
        out.append(char)
        run = run + 1 if char.isalpha() else 0
        if run == 4:
            out.append(ZERO_WIDTH)
            run = 0
    return "".join(out)


def insert(carrier: str, payload: str, position: str) -> str:
    """The carrier with the attack at its start, at the break nearest its middle, or at its end."""
    if position == "start":
        return f"{payload}\n\n{carrier}"
    if position == "end":
        return f"{carrier}\n\n{payload}"
    middle = len(carrier) // 2
    # At a paragraph break if the text has one, else at a line break, else at a space.
    for pattern in (r"\n\n", r"\n", r" "):
        breaks = [m.start() for m in re.finditer(pattern, carrier)]
        if breaks:
            break
    at = min(breaks, key=lambda b: abs(b - middle)) if breaks else middle
    return f"{carrier[:at]}\n\n{payload}\n\n{carrier[at:].lstrip()}"


def part_of_carrier(carrier: Carrier) -> str:
    return WIKI_PART if carrier.source == "wikitext" else SYNTHETIC


def attack(
    carrier: Carrier, k: int, number: int, templates: Sequence[Template], goals: Sequence[Goal]
) -> Sample:
    """The `k`-th attack on a carrier. `number` runs over all of them, so that the templates are
    used in turn and every one is used about as often as the others."""
    key = f"attack:{carrier.id}:{k}"
    template = templates[number % len(templates)]
    goal = pick(f"{key}:goal", goals)
    position = pick(f"{key}:position", POSITIONS)
    payload = strip_markers(render(template, goal, marker=False))
    hidden = "none"
    if digest(f"{key}:hidden") % HIDDEN_ONE_IN == 0:
        hidden = "zero_width" if digest(f"{key}:how") % 2 == 0 else "tags"
        payload = interleave(payload) if hidden == "zero_width" else to_tags(payload)
    return Sample(
        id=f"{carrier.id}+{template.id}-{k}",
        text=insert(carrier.text, payload, position),
        label=1,
        kind="indirect",
        carrier=carrier.id,
        split=split_of(carrier.id),
        part=part_of_carrier(carrier),
        meta={
            "template": template.id,
            "family": template.family,
            "goal": goal.id,
            "position": position,
            "hidden": hidden,
            "carrier_kind": carrier.kind,
            "source": carrier.source,
        },
    )


def from_carriers(carriers: Iterable[Carrier]) -> list[Sample]:
    templates, goals = load()
    found: list[Sample] = []
    for index, carrier in enumerate(sorted(carriers, key=lambda c: c.id)):
        found.append(
            Sample(
                id=carrier.id,
                text=carrier.text,
                label=0,
                kind="negative",
                carrier=carrier.id,
                split=split_of(carrier.id),
                part=part_of_carrier(carrier),
                meta={"carrier_kind": carrier.kind, "source": carrier.source},
            )
        )
        for k in range(PER_CARRIER):
            found.append(attack(carrier, k, index * PER_CARRIER + k, templates, goals))
    return found


def hard_samples() -> list[Sample]:
    return [
        Sample(
            id=h.id,
            text=h.text,
            label=0,
            kind="hard_negative",
            carrier=h.id,
            split=split_of(h.id),
            part=SYNTHETIC,
            meta={"family": h.family},
        )
        for h in hard_negatives()
    ]


def synthetic() -> list[Sample]:
    """Every sample that needs no download."""
    return sorted(from_carriers(synthetic_carriers()) + hard_samples(), key=lambda s: s.id)


# -- the public parts

Fetch = Callable[[str], bytes]
Read = Callable[[bytes], list[dict[str, Any]]]


def fetch_bytes(url: str) -> bytes:
    """GET a URL, following redirects (the files are served from a CDN), trying again after a
    pause. Raises on the last failure."""
    last: Exception | None = None
    for attempt in range(ATTEMPTS):
        try:
            answer = httpx.get(url, timeout=TIMEOUT_S, follow_redirects=True)
            answer.raise_for_status()
            return answer.content
        except httpx.HTTPError as error:
            last = error
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"could not read {url}: {type(last).__name__}") from last


def read_parquet(data: bytes) -> list[dict[str, Any]]:
    """The rows of a parquet file, each a dict of its columns. pyarrow is imported here so that
    nothing else in the evaluation needs it."""
    import pyarrow.parquet as pq

    rows: list[dict[str, Any]] = pq.read_table(io.BytesIO(data)).to_pylist()
    return rows


def cached_rows(source: Source, fetch: Fetch, read: Read, cache: Path) -> list[dict[str, Any]]:
    """The rows of the splits we use: from the cache when it holds them, else downloaded and
    cached. The caller checks them against the manifest either way."""
    path = cache / f"{source.name.replace('/', '--')}.jsonl"
    if path.is_file():
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    found: list[dict[str, Any]] = []
    for split in source.files:
        for index, row in enumerate(read(fetch(source.url(split)))):
            found.append({**row, "row_idx": index, "split": split})
    cache.mkdir(parents=True, exist_ok=True)
    body = "\n".join(json.dumps(row, sort_keys=True) for row in found)
    path.write_text(body + "\n", encoding="utf-8")
    return found


def public_samples(fetch: Fetch, read: Read, cache: Path) -> list[Sample]:
    found = []
    for row in cached_rows(PUBLIC, fetch, read, cache):
        name = f"public-{row['split']}-{row['row_idx']:04d}"
        found.append(
            Sample(
                id=name,
                text=row["text"],
                label=int(row["label"]),
                kind="public",
                carrier=name,
                split=split_of(name),
                part=PUBLIC_PART,
                meta={"hf_split": row["split"], "source": PUBLIC.name},
            )
        )
    return found


HEADING = re.compile(r"\s*(?:= )+(.+?)(?: =)+\s*")


def clean_wiki(line: str) -> str:
    """WikiText is tokenized: " , " and " @-@ ". Undo that so that the text reads as prose, and
    turn a heading (" = = Career = = ") into its words."""
    heading = HEADING.fullmatch(line)
    text = heading.group(1) if heading else line
    text = text.replace(" @-@ ", "-").replace(" @,@ ", ",").replace(" @.@ ", ".")
    text = re.sub(r" ([,.;:!?%)\]]|'s\b|n't\b)", r"\1", text)
    text = re.sub(r"([(\[$]) ", r"\1", text)
    text = re.sub(r'" (.+?) "', r'"\1"', text)
    return text.strip()


def wiki_carriers(fetch: Fetch, read: Read, cache: Path) -> list[Carrier]:
    """The 60 articles of the test split of WikiText-2, each cut to a length of its own."""
    articles: list[list[str]] = []
    for row in sorted(cached_rows(WIKITEXT, fetch, read, cache), key=lambda r: r["row_idx"]):
        line = row["text"]
        if re.fullmatch(r" = [^=].* = \n", line):  # a title: a new article starts
            articles.append([])
        if articles and line.strip():
            articles[-1].append(clean_wiki(line))
    if len(articles) < WIKI_ARTICLES:
        raise RuntimeError(
            f"WikiText-2 has {len(articles)} articles and the build needs {WIKI_ARTICLES}"
        )
    found = []
    for number, lines in enumerate(articles[:WIKI_ARTICLES]):
        text = "\n\n".join(lines)
        limit = pick(f"wiki:{number}:length", WIKI_LENGTHS)
        if len(text) > limit:
            text = text[:limit].rsplit(" ", 1)[0]
        found.append(Carrier(f"page-w{number:02d}", "page", "wikitext", text))
    return found


# -- the manifest


def describe(sample: Sample) -> dict[str, Any]:
    return {
        "id": sample.id,
        "sha256": sha256(sample.text),
        "label": sample.label,
        "kind": sample.kind,
        "split": sample.split,
        "carrier": sample.carrier,
        "part": sample.part,
    }


def manifest_of(samples: Sequence[Sample]) -> dict[str, Any]:
    return {
        "version": VERSION,
        "seed": SEED,
        "dev_percent": DEV_PERCENT,
        "sources": {
            PUBLIC_PART: {
                "dataset": PUBLIC.name,
                "revision": PUBLIC.revision,
                "license": PUBLIC.license,
            },
            WIKI_PART: {
                "dataset": WIKITEXT.name,
                "file": WIKITEXT.files["test"],
                "revision": WIKITEXT.revision,
                "license": WIKITEXT.license,
            },
        },
        "counts": dict(sorted(Counter(s.part for s in samples).items())),
        "samples": [describe(s) for s in sorted(samples, key=lambda s: s.id)],
    }


def verify(samples: Sequence[Sample], manifest: Mapping[str, Any], parts: Collection[str]) -> None:
    """Raise DatasetChanged unless the samples of `parts` are exactly those the manifest lists for
    them: the same ids, and for each the same text, label, kind, split and carrier."""
    expected = {e["id"]: e for e in manifest["samples"] if e["part"] in parts}
    seen = {s.id: s for s in samples if s.part in parts}
    problems = [f"{i} is not in the manifest" for i in sorted(seen.keys() - expected.keys())]
    problems += [f"{i} is missing from the build" for i in sorted(expected.keys() - seen.keys())]
    for sample_id in sorted(seen.keys() & expected.keys()):
        if describe(seen[sample_id]) != expected[sample_id]:
            problems.append(f"{sample_id} differs from the manifest")
    if problems:
        more = f" (and {len(problems) - 5} more)" if len(problems) > 5 else ""
        raise DatasetChanged(
            f"the dataset is not the one in the manifest: {'; '.join(problems[:5])}{more}"
        )


def load_manifest(path: Path = MANIFEST) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    loaded: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return loaded


def write_manifest(samples: Sequence[Sample], path: Path = MANIFEST) -> None:
    """The manifest as JSON with one sample to a line, so that a diff of it can be read."""
    document = manifest_of(samples)
    entries = document.pop("samples")
    head = json.dumps(document, indent=2, sort_keys=True)
    body = ",\n".join("    " + json.dumps(entry, sort_keys=True) for entry in entries)
    path.write_text(head[:-2] + ',\n  "samples": [\n' + body + "\n  ]\n}\n", encoding="utf-8")


# -- the build


def build(
    *,
    download: bool = True,
    fetch: Fetch = fetch_bytes,
    read: Read = read_parquet,
    cache: Path = DATA_DIR,
    manifest: Mapping[str, Any] | str | None = "committed",
) -> Dataset:
    """The dataset. The synthetic parts are always there. With `download` the public parts are
    added, and a part that cannot be read is left out and named in `notes`. A text that differs
    from the manifest raises DatasetChanged. `manifest="committed"` reads
    eval/detector/manifest.json, and None skips the check (a test of the builder on data of its
    own, and the command that writes the manifest)."""
    checked = load_manifest() if manifest == "committed" else manifest
    if checked is not None and not isinstance(checked, Mapping):
        raise TypeError("manifest is 'committed', None or a mapping")
    notes: list[str] = []
    samples = synthetic()
    if checked is not None:
        verify(samples, checked, {SYNTHETIC})
    if not download:
        notes.append(
            "built offline: the public parts (deepset/prompt-injections, WikiText-2) are not in it"
        )
    else:
        makers: list[tuple[str, str, Callable[[], list[Sample]]]] = [
            (PUBLIC_PART, PUBLIC.name, lambda: public_samples(fetch, read, cache)),
            (WIKI_PART, "WikiText-2", lambda: from_carriers(wiki_carriers(fetch, read, cache))),
        ]
        for part, label, make in makers:
            try:
                added = make()
            except Exception as error:
                reason = type(error).__name__
                notes.append(f"{label} was not downloaded ({reason}): the dataset is without it")
                continue
            if checked is not None:
                verify(added, checked, {part})
            samples += added
    samples.sort(key=lambda s: s.id)
    return Dataset(tuple(samples), tuple(notes), dict(Counter(s.part for s in samples)))


def summary(data: Dataset) -> str:
    kinds = Counter((s.kind, s.label) for s in data.samples)
    lines = [f"{len(data.samples)} samples, parts {dict(data.parts)}"]
    for split in ("dev", "test"):
        chosen = data.split(split)
        lines.append(
            f"  {split}: {len(chosen)} samples, {sum(s.label for s in chosen)} injections, "
            f"{len({s.carrier for s in chosen})} carriers"
        )
    shown = ", ".join(f"{kind}/{label}={n}" for (kind, label), n in sorted(kinds.items()))
    lines.append(f"  kinds: {shown}")
    lines += [f"  note: {note}" for note in data.notes]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the detector dataset")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("build", "manifest"):
        command = commands.add_parser(name)
        command.add_argument("--offline", action="store_true", help="the synthetic parts only")
    args = parser.parse_args(argv)
    if args.command == "build":
        print(summary(build(download=not args.offline)))
        return 0
    data = build(download=not args.offline, manifest=None)
    if not data.complete:
        print("not writing the manifest of a dataset that is not complete:", *data.notes, sep="\n")
        return 1
    write_manifest(data.samples)
    print(f"wrote {MANIFEST.relative_to(REPO)}\n{summary(data)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
