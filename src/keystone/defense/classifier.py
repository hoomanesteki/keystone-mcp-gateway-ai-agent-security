"""A classifier that scores text for injection, behind the rules (KS-702, ADR-0011).

The scanner asks a classifier for a number between 0 and 1, the chance that a text is an
injection. A classifier that cannot answer in time returns None, and the scanner goes on with the
rules alone and says so (`model="timeout"`).

`HFClassifier` runs a Hugging Face text-classification model on the CPU. Everything it needs comes
from the optional extra `keystone[scanner]` (torch and transformers), and nothing in this module
imports either at the top: the module has to load where the extra is not installed, which is every
CI job. The pieces are small on purpose, so that all of them but the last can be tested without a
model:

- `split_windows` and `pick_windows` cut a long text into overlapping windows of tokens.
- `injection_indexes` says which outputs of the model mean "injection", from its own labels.
- `WindowedEngine` scores a text as the highest window, with a tokenizer and a model given to it.
- `Place` is one place in the limit on scans that run at once.
- `HFClassifier` loads the model on first use, in a thread, and runs each scan in a thread.
- `build_engine` is the part that touches torch and transformers.

A scan that stops waiting (the scanner's timeout) cannot stop a thread by force. The thread checks
between batches whether it was abandoned and leaves, and the place it held comes back to the limit
when the thread has left, not when the caller gave up, so abandoned scans cannot pile up.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import importlib
import importlib.util
import json
import os
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Literal, Protocol

import anyio
import anyio.from_thread
import structlog

from keystone.settings import ScannerSettings

log = structlog.get_logger()

Role = Literal["benign", "injection"]

# A window holds the special tokens at its two ends, so it holds two fewer of the text's own.
SPECIAL_TOKENS = 2
MAX_LENGTH = 512
STRIDE = 64
BATCH_SIZE = 4
# A text of more windows than this is sampled across its length. Nothing gets that far in the
# time a scan is given, and an abandoned scan stops at its next batch in any case.
MAX_WINDOWS = 32
# Once a window is this sure, the others cannot change the answer by enough to matter.
SURE = 0.99


class Classifier(Protocol):
    """Names itself in `ScanResult.model`, and scores a text. None means "no answer"."""

    name: str

    async def score(self, text: str) -> float | None: ...


class ClassifierUnavailable(RuntimeError):
    """The model cannot be used: the extra is not installed, or it did not load."""


class ClassifierBusy(Exception):
    """Every place for a scan is taken. The scanner leaves the model out of this scan (`model` says
    "busy") and the rules decide: waiting would spend the call's time on a queue the model cannot
    clear, and a scan that cannot start must not hold the call back (KS-992)."""


@dataclass(frozen=True)
class ClassifierSpec:
    """A model the scanner knows, pinned to a revision."""

    key: str
    model_id: str
    revision: str
    # Each label the model has, and what it means. A label missing here stops the load.
    labels: Mapping[str, Role]


# What `fetch` downloads: the weights, the configuration and the tokenizer, and nothing else (the
# ProtectAI repository also holds an ONNX copy of the model).
FILES = (
    "config.json",
    "*.safetensors",
    "tokenizer*",
    "special_tokens_map.json",
    "added_tokens.json",
    "spm.model",
)

SPECS: dict[str, ClassifierSpec] = {
    "protectai-deberta-v2": ClassifierSpec(
        key="protectai-deberta-v2",
        model_id="protectai/deberta-v3-base-prompt-injection-v2",
        revision="90c9989b1a342275dd0d1a95aad283c04e075671",
        labels={"SAFE": "benign", "INJECTION": "injection"},
    ),
    # Gated: the Llama license has to be accepted on Hugging Face, and its card cannot be read
    # without that. The labels are not checked against its config. If they are wrong the load
    # stops and names the labels the model has (injection_indexes), so a wrong guess is loud.
    "prompt-guard-2-86m": ClassifierSpec(
        key="prompt-guard-2-86m",
        model_id="meta-llama/Llama-Prompt-Guard-2-86M",
        revision="a8ded8e697ce7c355e395a0df51f94adb4a2fd27",
        labels={"LABEL_0": "benign", "LABEL_1": "injection"},
    ),
}


def injection_indexes(id2label: Mapping[int, str], labels: Mapping[str, str]) -> list[int]:
    """The outputs of the model that mean injection, from the labels in its own config. A label
    that `labels` does not name is an error, so a model that was retrained with another set of
    labels cannot be read the wrong way round."""
    unknown = sorted(name for name in id2label.values() if name not in labels)
    if unknown:
        raise ValueError(f"the model has labels that are not mapped: {', '.join(unknown)}")
    found = sorted(index for index, name in id2label.items() if labels[name] == "injection")
    if not found:
        raise ValueError("no label of the model means injection")
    return found


def split_windows(count: int, size: int, stride: int) -> list[tuple[int, int]]:
    """Windows over `count` tokens, `size` long at most, each sharing `stride` tokens with the one
    before. The first starts at 0 and the last ends at `count`."""
    if not 0 <= stride < size:
        raise ValueError(f"stride must be from 0 to less than the window size {size}, not {stride}")
    if count <= 0:
        return []
    spans: list[tuple[int, int]] = []
    start = 0
    while True:
        end = min(start + size, count)
        spans.append((start, end))
        if end == count:
            return spans
        start += size - stride


def pick_windows(spans: Sequence[tuple[int, int]], limit: int) -> list[tuple[int, int]]:
    """At most `limit` of the windows, spread over the whole text, first and last included."""
    if len(spans) <= limit:
        return list(spans)
    if limit < 2:
        return list(spans[:1])
    last = len(spans) - 1
    return [spans[index] for index in sorted({round(i * last / (limit - 1)) for i in range(limit)})]


def stop_if_abandoned() -> None:
    """Called by a scan in a worker thread: raises when the caller has stopped waiting. Outside a
    worker thread there is nobody to have stopped waiting, and it does nothing."""
    try:
        anyio.from_thread.check_cancelled()
    except anyio.NoEventLoopError:
        return


@dataclass
class WindowedEngine:
    """Scores a text as the highest of its windows. `tokenize` turns text into token ids with no
    special tokens, and `infer` turns rows of ids (each with its special tokens) into one chance of
    injection per row. Neither knows about windows."""

    tokenize: Callable[[str], list[int]]
    infer: Callable[[list[list[int]]], list[float]]
    cls_id: int
    sep_id: int
    max_length: int = MAX_LENGTH
    stride: int = STRIDE
    batch_size: int = BATCH_SIZE
    max_windows: int = MAX_WINDOWS

    def score(self, text: str) -> float:
        ids = self.tokenize(text)
        spans = pick_windows(
            split_windows(len(ids), self.max_length - SPECIAL_TOKENS, self.stride),
            self.max_windows,
        )
        best = 0.0
        for first in range(0, len(spans), self.batch_size):
            stop_if_abandoned()
            rows = [
                [self.cls_id, *ids[start:end], self.sep_id]
                for start, end in spans[first : first + self.batch_size]
            ]
            best = max(best, *self.infer(rows))
            if best >= SURE:
                break
        return best


class Engine(Protocol):
    def score(self, text: str) -> float: ...


class Place:
    """One place in the limit on scans that run at once. It is given back once: by the caller, if
    it stopped waiting before any thread took the work, and by the thread if one did, when it
    leaves. A thread that arrives after the caller left does nothing."""

    def __init__(self, release: Callable[[], object]) -> None:
        self._release = release
        self._lock = threading.Lock()
        self._state: Literal["waiting", "running", "done"] = "waiting"

    def begin(self) -> bool:
        """The thread is about to work. False means the caller already gave the place back."""
        with self._lock:
            if self._state != "waiting":
                return False
            self._state = "running"
            return True

    def leave(self) -> None:
        """The caller stops waiting for the thread."""
        with self._lock:
            if self._state != "waiting":
                return
            self._state = "done"
        self._release()

    def finish(self) -> None:
        """The thread is done, however it ended."""
        with self._lock:
            if self._state == "done":
                return
            self._state = "done"
        self._release()


@dataclass
class _Loading:
    """Where a classifier is in loading its model. Made on the first scan, inside the event loop
    that will use it."""

    ready: anyio.Event
    places: anyio.Semaphore
    engine: Engine | None = None
    failure: ClassifierUnavailable | None = None


class HFClassifier:
    """A Hugging Face text-classification model on the CPU.

    The model loads on first use, in a thread, and the load goes on if the scan that asked for it
    gives up, so the first scans after a start may find no answer and fall back to the rules.
    `warm` loads it before the first scan. Scans run in worker threads, no more at once than
    `concurrency` (the CPU count). The scanner's timeout is what bounds how long a caller waits.
    """

    def __init__(
        self,
        model_id: str,
        labels_map: Mapping[str, str],
        max_length: int = MAX_LENGTH,
        stride: int = STRIDE,
        *,
        name: str | None = None,
        revision: str | None = None,
        batch_size: int = BATCH_SIZE,
        concurrency: int | None = None,
        threads: int | None = None,
        loader: Callable[[], Engine] | None = None,
    ) -> None:
        self.name = name or model_id
        # How a long text is cut for the model: tokens in a window with the two special tokens, and
        # tokens shared with the window before (`scanner.window_tokens` and `window_overlap`).
        self.max_length = max_length
        self.stride = stride
        self._loader: Callable[[], Engine] = loader or partial(
            build_engine, model_id, revision, labels_map, max_length, stride, batch_size, threads
        )
        self._concurrency = concurrency or os.cpu_count() or 1
        self._loading: _Loading | None = None

    @property
    def loaded(self) -> bool:
        return self._loading is not None and self._loading.engine is not None

    async def warm(self) -> None:
        """Wait until the model is loaded. Raises ClassifierUnavailable if it cannot be."""
        await self._ready()

    async def score(self, text: str) -> float:
        loading = await self._ready()
        engine = loading.engine
        if engine is None:  # `_ready` raises before this, so this is for the type checker
            raise ClassifierUnavailable(f"{self.name} has no model")
        try:
            loading.places.acquire_nowait()
        except anyio.WouldBlock:
            raise ClassifierBusy from None
        loop = asyncio.get_running_loop()

        def give_back() -> None:
            # A closed loop means the process is going away, and the place with it.
            with contextlib.suppress(RuntimeError):
                loop.call_soon_threadsafe(loading.places.release)

        place = Place(give_back)

        def work() -> float:
            if not place.begin():
                return 0.0
            try:
                return engine.score(text)
            finally:
                place.finish()

        try:
            return await anyio.to_thread.run_sync(work, abandon_on_cancel=True)
        finally:
            place.leave()

    async def _ready(self) -> _Loading:
        loading = self._loading
        if loading is None:
            loading = self._loading = _Loading(anyio.Event(), anyio.Semaphore(self._concurrency))
            self._start_loading(asyncio.get_running_loop(), loading)
        await loading.ready.wait()
        if loading.failure is not None:
            raise loading.failure
        return loading

    def _start_loading(self, loop: asyncio.AbstractEventLoop, loading: _Loading) -> None:
        def load() -> None:
            try:
                loading.engine = self._loader()
            except ImportError as error:
                loading.failure = ClassifierUnavailable(
                    f"{self.name} needs the scanner extra, install keystone[scanner]: {error}"
                )
                log.error("scanner_classifier_not_loaded", classifier=self.name, reason="import")
            except Exception as error:
                loading.failure = ClassifierUnavailable(f"{self.name} did not load: {error}")
                log.error(
                    "scanner_classifier_not_loaded",
                    classifier=self.name,
                    error=type(error).__name__,
                )
            finally:
                with contextlib.suppress(RuntimeError):
                    loop.call_soon_threadsafe(loading.ready.set)

        threading.Thread(target=load, name=f"classifier-{self.name}", daemon=True).start()


class FakeClassifier:
    """A classifier for tests: `score_fn` decides the answer, `delay_s` makes it slow, and `asked`
    keeps every text it was given."""

    def __init__(
        self,
        score_fn: Callable[[str], float | None],
        *,
        name: str = "fake",
        delay_s: float = 0.0,
        places: int | None = None,
    ) -> None:
        self.name = name
        self.asked: list[str] = []
        self._score_fn = score_fn
        self._delay_s = delay_s
        # Like the places of HFClassifier: a scan that finds them all taken is busy.
        self._free = places

    async def score(self, text: str) -> float | None:
        if self._free is not None:
            if self._free <= 0:
                raise ClassifierBusy
            self._free -= 1
        self.asked.append(text)
        try:
            if self._delay_s:
                await anyio.sleep(self._delay_s)
            return self._score_fn(text)
        finally:
            if self._free is not None:
                self._free += 1


def build_engine(
    model_id: str,
    revision: str | None,
    labels_map: Mapping[str, str],
    max_length: int,
    stride: int,
    batch_size: int,
    threads: int | None = None,
) -> WindowedEngine:
    """Load the model and its tokenizer and wrap them. This is the one place that imports torch
    and transformers, by name at run time, so that neither is needed to import this module or to
    type check it."""
    torch = importlib.import_module("torch")
    transformers = importlib.import_module("transformers")
    if threads is not None:
        # torch sizes its pool by the host's CPUs, not the container's (see `available_cpus`).
        torch.set_num_threads(threads)
    tokenizer = transformers.AutoTokenizer.from_pretrained(model_id, revision=revision)
    model = transformers.AutoModelForSequenceClassification.from_pretrained(
        model_id, revision=revision
    )
    model.eval()
    indexes = injection_indexes(
        {int(index): name for index, name in model.config.id2label.items()}, labels_map
    )
    cls_id, sep_id, pad_id = tokenizer.cls_token_id, tokenizer.sep_token_id, tokenizer.pad_token_id
    if not all(isinstance(token, int) for token in (cls_id, sep_id, pad_id)):
        raise ValueError("the tokenizer has no CLS, SEP or PAD token")

    def tokenize(text: str) -> list[int]:
        encoded = tokenizer(text, add_special_tokens=False, return_attention_mask=False)
        return [int(token) for token in encoded["input_ids"]]

    def infer(rows: list[list[int]]) -> list[float]:
        width = max(len(row) for row in rows)
        input_ids = torch.tensor([row + [pad_id] * (width - len(row)) for row in rows])
        attention = torch.tensor([[1] * len(row) + [0] * (width - len(row)) for row in rows])
        with torch.inference_mode():
            logits = model(input_ids=input_ids, attention_mask=attention).logits
            chance = torch.softmax(logits, dim=-1)[:, indexes].sum(dim=-1)
        return [float(value) for value in chance]

    return WindowedEngine(
        tokenize,
        infer,
        cls_id,
        sep_id,
        max_length=max_length,
        stride=stride,
        batch_size=batch_size,
    )


def available_cpus() -> int:
    """The CPUs this process may use: the container's limit when there is one, else the host's.
    `os.cpu_count()` reports the host (the Docker VM), so a container limited to 4 CPUs on 10 would
    size its thread pools for 10 and be throttled by the kernel, which stops the event loop too."""
    count = os.cpu_count() or 1
    affinity = getattr(os, "sched_getaffinity", None)  # not on macOS
    if affinity is not None:
        with contextlib.suppress(OSError):
            count = min(count, len(affinity(0)))
    for path in ("/sys/fs/cgroup/cpu.max", "/sys/fs/cgroup/cpu/cpu.cfs_quota_us"):
        try:
            parts = Path(path).read_text().split()
            if path.endswith("cpu.max"):
                quota, period = parts[0], parts[1]
            else:
                quota = parts[0]
                period = Path("/sys/fs/cgroup/cpu/cpu.cfs_period_us").read_text().strip()
            if quota not in ("max", "-1"):
                count = min(count, max(1, round(int(quota) / int(period))))
            break
        except (OSError, ValueError, IndexError):
            continue
    return count


def classifier_limits(cfg: ScannerSettings, cpus: int | None = None) -> tuple[int, int]:
    """`(scans at once, threads for each)`. One CPU stays with the event loop. Few CPUs run one
    scan at a time with all the threads there are, because two scans at half the threads each both
    miss the scanner's timeout; from four spare CPUs, two scans run side by side."""
    spare = max(1, (cpus if cpus is not None else available_cpus()) - 1)
    concurrency = cfg.classifier_concurrency or (1 if spare < 4 else 2)
    threads = cfg.classifier_threads or max(1, spare // concurrency)
    return concurrency, threads


def load_classifier(cfg: ScannerSettings) -> Classifier | None:
    """The classifier the settings ask for, or None: `none` turns it off, and without the extra the
    scanner runs on its rules alone and says so once, loudly. The model is not loaded here."""
    if cfg.classifier == "none":
        return None
    spec = SPECS[cfg.classifier]
    missing = [m for m in ("torch", "transformers") if importlib.util.find_spec(m) is None]
    if missing:
        log.warning(
            "scanner_classifier_unavailable",
            classifier=spec.key,
            missing=missing,
            effect="rules only",
            fix="install keystone[scanner], or set scanner.classifier to none",
        )
        return None
    concurrency, threads = classifier_limits(cfg)
    return HFClassifier(
        spec.model_id,
        spec.labels,
        max_length=cfg.window_tokens + SPECIAL_TOKENS,
        stride=cfg.window_overlap,
        name=spec.key,
        revision=spec.revision,
        concurrency=concurrency,
        threads=threads,
    )


async def warm_up(classifier: Classifier, on_ready: Callable[[str], None] | None = None) -> None:
    """Load the model in the background when the gateway starts, so that the first scans of a
    call do not find it still loading and fall back to the rules (ADR-0011). A classifier with no
    `warm` has nothing to load. A model that cannot be loaded is logged once and never stops the
    gateway: each scan then reports `model: "error"` and the rules decide. `on_ready` is called
    with the name of the model once it has loaded, so that the gateway can say so."""
    warm = getattr(classifier, "warm", None)
    if warm is None:
        return
    try:
        await warm()
    except Exception as error:
        log.error(
            "scanner_classifier_not_ready", classifier=classifier.name, error=type(error).__name__
        )
        return
    log.info("scanner_classifier_ready", classifier=classifier.name)
    if on_ready is not None:
        on_ready(classifier.name)


def fetch_model(spec: ClassifierSpec) -> str:
    """Download the files of the model into the Hugging Face cache and return where they are.
    The Docker build runs this, so that the container never goes to the network for them."""
    hub = importlib.import_module("huggingface_hub")
    path = hub.snapshot_download(spec.model_id, revision=spec.revision, allow_patterns=list(FILES))
    return str(path)


def real_id2label(spec: ClassifierSpec) -> dict[int, str]:
    """The labels in the model's own config.json (downloaded if it is not in the cache)."""
    hub = importlib.import_module("huggingface_hub")
    path = hub.hf_hub_download(spec.model_id, "config.json", revision=spec.revision)
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    return {int(index): name for index, name in config["id2label"].items()}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Work with the scanner's classifier models")
    commands = parser.add_subparsers(dest="command", required=True)
    fetch = commands.add_parser("fetch", help="download a model into the Hugging Face cache")
    fetch.add_argument("key", nargs="?", default="protectai-deberta-v2", choices=sorted(SPECS))
    args = parser.parse_args(argv)
    print(fetch_model(SPECS[args.key]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
