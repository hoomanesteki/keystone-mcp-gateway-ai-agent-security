"""Run code an agent wrote in a locked-down container (KS-801, ADR-0012).

One call is one container. It is created with the flags below, started, read until it ends or
its time is up, and removed. Nothing is reused, so a script cannot leave anything for the next
one.

The flags (`container_config`, and a test inspects them on a running container through the Docker
API):

- no network at all: `network_mode=none`, so there is a loopback and no route
- a read-only root, with a tmpfs of 64 MB on `/tmp` (no exec) and on `/workspace`
- 512 MB of memory and no swap, one CPU, 128 processes
- every capability dropped, `no-new-privileges`, and user 10001, which owns nothing in the image
- a runtime chosen by the operator: `runc`, or `runsc` where gVisor is installed
- the labels `keystone.sandbox=1` and `keystone.call_id=<id>`, which the reaper and an operator
  with `docker ps` read

Everything goes through the Docker API. Keystone itself runs in a container, so a path in this
process is not a path on the host that the daemon sees: there is no bind mount, the code goes in
as an argument, the input goes in on stdin, and the output comes back on the attach stream. The
container's log driver is `none`, so what a script prints is held here and nowhere on the host.

Output is capped at 64 KB for stdout and for stderr. A script that writes more is not stopped for
it: the rest is read and dropped, and the result says `truncated`. One that writes 32 MB is
killed, because reading without end is a way to keep a CPU busy.

Docker is a boundary for scripts a model wrote, with these flags. It is not one for hostile code
from many tenants: containers share the host's kernel. For that, `runtime: runsc` (gVisor) puts a
second kernel between the script and the host, and a microVM does more. ADR-0012 says where the
line is.

The Docker SDK blocks, so every call to it runs in a thread. Keystone's own concurrency is bounded
(`max_concurrent`), and a run that is cancelled (the client left) is killed and removed.
"""

from __future__ import annotations

import contextlib
import socket
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from typing import Any

import anyio
import docker
import structlog
from docker.errors import APIError, DockerException, ImageNotFound, NotFound
from docker.types import LogConfig

from keystone.core.ids import new_id

log = structlog.get_logger()

SANDBOX_LABEL = "keystone.sandbox"
CALL_LABEL = "keystone.call_id"

# Plan KS-801. Not settings: a deployment that can weaken them is a deployment that will.
USER = "10001:10001"
MEMORY = "512m"
NANO_CPUS = 1_000_000_000
PIDS_LIMIT = 128
TMPFS = {"/tmp": "size=64m,noexec", "/workspace": "size=64m"}  # noqa: S108 - inside the container
WORKDIR = "/workspace"

MAX_OUTPUT_BYTES = 64 * 1024
# Reading without end keeps a thread busy. A script that wrote this much is killed.
MAX_STREAM_BYTES = 32 * 1024 * 1024
MAX_STDIN_BYTES = 1024 * 1024
MAX_TIMEOUT_S = 300.0
# How often a read wakes to look at the clock and at a cancellation.
POLL_S = 0.2
# What a killed container is given to close its stream and report an exit code.
KILL_GRACE_S = 5.0
DRAIN_S = 3.0
API_TIMEOUT_S = 30.0
# What the reaper removes, and how often it looks (plan KS-801).
REAP_AFTER_S = 600.0
REAP_EVERY_S = 60.0

STDOUT, STDERR = 1, 2
HEADER_BYTES = 8


class SandboxError(Exception):
    """A run could not be made or finished. The message is for the log: it can hold a path or
    an address, and the agent is told none of it."""


class SandboxUnavailable(SandboxError):
    """The sandbox cannot run anything now: the daemon cannot be reached, the image is not built,
    or the runtime is not installed."""


@dataclass(frozen=True)
class SandboxResult:
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool
    truncated: bool
    duration_ms: float


def container_config(
    image: str,
    cmd: Sequence[str],
    *,
    runtime: str = "runc",
    call_id: str,
    stdin_open: bool = False,
) -> dict[str, Any]:
    """The arguments to `containers.create`. Every hardening flag is here and nowhere else."""
    return {
        "image": image,
        "command": list(cmd),
        "network_mode": "none",
        "read_only": True,
        "tmpfs": dict(TMPFS),
        "mem_limit": MEMORY,
        "memswap_limit": MEMORY,
        "nano_cpus": NANO_CPUS,
        "pids_limit": PIDS_LIMIT,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges"],
        "user": USER,
        "runtime": runtime,
        "labels": {SANDBOX_LABEL: "1", CALL_LABEL: call_id},
        "working_dir": WORKDIR,
        "privileged": False,
        # What a script prints stays in this process. With a log driver the daemon would also write
        # all of it to a file on the host.
        "log_config": LogConfig(type="none"),
        # With stdin open the SDK also sets StdinOnce, so the input ends when the writer does.
        "stdin_open": stdin_open,
        "tty": False,
    }


class OutputCollector:
    """Splits Docker's multiplexed stream into stdout and stderr. Each frame is a header of 8
    bytes (the stream, three zeros, the length as a big-endian number) and the bytes. The first
    `limit` bytes of each stream are kept and the rest are counted and dropped. It takes the
    stream in chunks of any size."""

    def __init__(self, limit: int = MAX_OUTPUT_BYTES, flood_at: int = MAX_STREAM_BYTES) -> None:
        self._limit = limit
        self._flood_at = flood_at
        self._header = bytearray()
        self._stream = 0
        self._left = 0
        self._kept = {STDOUT: bytearray(), STDERR: bytearray()}
        self.total = 0
        self.truncated = False

    @property
    def flooded(self) -> bool:
        return self.total >= self._flood_at

    @property
    def stdout(self) -> bytes:
        return bytes(self._kept[STDOUT])

    @property
    def stderr(self) -> bytes:
        return bytes(self._kept[STDERR])

    def feed(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            if self._left == 0:
                take = view[: HEADER_BYTES - len(self._header)]
                self._header += take
                view = view[len(take) :]
                if len(self._header) < HEADER_BYTES:
                    return
                self._stream = self._header[0]
                self._left = int.from_bytes(self._header[4:8], "big")
                self._header.clear()
                continue
            chunk = view[: self._left]
            view = view[len(chunk) :]
            self._left -= len(chunk)
            self._keep(self._stream, bytes(chunk))

    def _keep(self, stream: int, chunk: bytes) -> None:
        self.total += len(chunk)
        kept = self._kept.get(stream)
        if kept is None:
            return  # the echo of stdin, or a stream this version does not know
        room = self._limit - len(kept)
        if len(chunk) > room:
            self.truncated = True
        if room > 0:
            kept += chunk[:room]


def _text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _stdin_bytes(stdin: str | bytes | None) -> bytes:
    data = stdin.encode() if isinstance(stdin, str) else (stdin or b"")
    if len(data) > MAX_STDIN_BYTES:
        raise ValueError(f"stdin is {len(data)} bytes, the limit is {MAX_STDIN_BYTES}")
    return data


def _created_at(attributes: dict[str, Any]) -> float | None:
    """When a container was made, from the list endpoint (seconds) or from inspect (an RFC 3339
    text in UTC, with nanoseconds, which `datetime` does not read)."""
    created = attributes.get("Created")
    if isinstance(created, int | float):
        return float(created)
    if not isinstance(created, str):
        return None
    head, _, fraction = created.strip().removesuffix("Z").partition(".")
    digits = "".join(ch for ch in fraction if ch.isdigit())[:6]
    try:
        moment = datetime.fromisoformat(f"{head}.{digits}" if digits else head)
    except ValueError:
        return None
    return moment.replace(tzinfo=UTC).timestamp()


class SandboxRunner:
    def __init__(
        self,
        client: Any = None,
        *,
        runtime: str = "runc",
        max_concurrent: int = 4,
        base_url: str | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """`client` is a Docker client, for a test or a caller that has one. Without it the client
        is made on first use, from `base_url` or from the environment (DOCKER_HOST), so building
        a runner never needs a daemon."""
        if max_concurrent < 1:
            raise ValueError("max_concurrent must be at least 1")
        self._client = client
        self._lock = threading.Lock()
        self._runtime = runtime
        self._max_concurrent = max_concurrent
        self._base_url = base_url
        self._clock = clock
        # Made on first use: a limiter belongs to the event loop that runs it.
        self._limiter: anyio.CapacityLimiter | None = None

    @property
    def runtime(self) -> str:
        return self._runtime

    def docker(self) -> Any:
        """The Docker client, made on first use. Raises SandboxUnavailable when there is no
        daemon to talk to. Blocking: call it from a thread."""
        with self._lock:
            if self._client is None:
                try:
                    if self._base_url:
                        self._client = docker.DockerClient(
                            base_url=self._base_url, timeout=API_TIMEOUT_S
                        )
                    else:
                        self._client = docker.from_env(timeout=API_TIMEOUT_S)
                except (DockerException, OSError) as error:
                    raise SandboxUnavailable(
                        f"the Docker daemon cannot be reached ({type(error).__name__})"
                    ) from None
            return self._client

    # -- running

    async def run(
        self,
        image: str,
        cmd: Sequence[str],
        stdin: str | bytes | None = None,
        timeout_s: float = 30.0,
        *,
        call_id: str | None = None,
    ) -> SandboxResult:
        """Run `cmd` in a new container of `image` and return what it did. `stdin` is written to
        its standard input, which is then closed. A run still going after `timeout_s` is killed
        and says so. Raises SandboxUnavailable when nothing can be run, SandboxError when a run
        broke, ValueError for arguments that make no sense."""
        if not cmd:
            raise ValueError("cmd needs at least a program")
        if not 0 < timeout_s <= MAX_TIMEOUT_S:
            raise ValueError(f"timeout_s must be above 0 and at most {MAX_TIMEOUT_S:g}")
        data = _stdin_bytes(stdin)
        if self._limiter is None:
            self._limiter = anyio.CapacityLimiter(self._max_concurrent)
        cancelled = threading.Event()
        job = partial(
            self._execute, image, list(cmd), data, timeout_s, call_id or new_id(), cancelled
        )
        try:
            # Abandoned on cancellation: the thread kills its container when it sees the event.
            return await anyio.to_thread.run_sync(
                job, abandon_on_cancel=True, limiter=self._limiter
            )
        finally:
            cancelled.set()

    def _execute(
        self,
        image: str,
        cmd: list[str],
        stdin: bytes,
        timeout_s: float,
        call_id: str,
        cancelled: threading.Event,
    ) -> SandboxResult:
        client = self.docker()
        config = container_config(
            image, cmd, runtime=self._runtime, call_id=call_id, stdin_open=bool(stdin)
        )
        try:
            container = client.containers.create(**config)
        except ImageNotFound:
            raise SandboxUnavailable(f"the image {image} is not built") from None
        except (DockerException, OSError) as error:
            raise SandboxUnavailable(f"a container could not be made ({_why(error)})") from None
        try:
            return self._collect(client, container, stdin, timeout_s, call_id, cancelled)
        finally:
            self._remove(container)

    def _collect(
        self,
        client: Any,
        container: Any,
        stdin: bytes,
        timeout_s: float,
        call_id: str,
        cancelled: threading.Event,
    ) -> SandboxResult:
        started = time.monotonic()
        # Attached before the start, so no byte of output is missed.
        params = {"stream": 1, "stdin": 1 if stdin else 0, "stdout": 1, "stderr": 1}
        try:
            attached = client.api.attach_socket(container.id, params=params)
            sock = getattr(attached, "_sock", attached)
            container.start()
        except (DockerException, OSError) as error:
            raise SandboxUnavailable(f"the container did not start ({_why(error)})") from None
        collector = OutputCollector()
        try:
            if stdin:
                threading.Thread(
                    target=_feed, args=(sock, stdin), name="sandbox-stdin", daemon=True
                ).start()
            timed_out = self._read(sock, container, collector, started + timeout_s, cancelled)
        finally:
            _close(sock)
            _close(attached)
        exit_code = self._exit_code(client, container)
        duration_ms = (time.monotonic() - started) * 1000
        log.info(
            "sandbox_run",
            call_id=call_id,
            exit_code=exit_code,
            timed_out=timed_out,
            truncated=collector.truncated,
            duration_ms=round(duration_ms, 1),
        )
        return SandboxResult(
            stdout=_text(collector.stdout),
            stderr=_text(collector.stderr),
            exit_code=exit_code,
            timed_out=timed_out,
            truncated=collector.truncated,
            duration_ms=duration_ms,
        )

    def _read(
        self,
        sock: socket.socket,
        container: Any,
        collector: OutputCollector,
        deadline: float,
        cancelled: threading.Event,
    ) -> bool:
        """Read the stream until the container ends it. Kills the container when the time is up,
        when the caller has gone, or when the output never stops, and then reads on for a moment
        to take what was written before. Returns whether it was the time.

        The kill is made from another thread and this one keeps reading. The daemon does not report
        a container as stopped until everything it wrote has been copied to the readers, so a kill
        made by a thread that has stopped reading waits for itself."""
        sock.settimeout(POLL_S)
        timed_out = False
        killed_at: float | None = None
        while True:
            now = time.monotonic()
            if killed_at is None:
                timed_out = now >= deadline
                if timed_out or cancelled.is_set() or collector.flooded:
                    collector.truncated = collector.truncated or collector.flooded
                    threading.Thread(
                        target=self._kill, args=(container,), name="sandbox-kill", daemon=True
                    ).start()
                    killed_at = now
            elif now - killed_at >= DRAIN_S:
                return timed_out
            try:
                chunk = sock.recv(65536)
            except TimeoutError:
                continue
            except OSError:
                return timed_out
            if not chunk:
                return timed_out
            collector.feed(chunk)

    @staticmethod
    def _kill(container: Any) -> None:
        try:
            container.kill()
        except (NotFound, APIError):
            pass  # it ended by itself first
        except (DockerException, OSError) as error:
            log.warning("sandbox_kill_failed", error=type(error).__name__)

    @staticmethod
    def _exit_code(client: Any, container: Any) -> int:
        try:
            waited = container.wait(timeout=KILL_GRACE_S)
            return int(waited["StatusCode"])
        except Exception as error:
            log.debug("sandbox_wait_failed", error=type(error).__name__)
        try:
            state = client.api.inspect_container(container.id)["State"]
        except Exception as error:
            raise SandboxError(f"the exit code is unknown ({type(error).__name__})") from None
        if state.get("Running"):
            raise SandboxError("the container did not stop")
        return int(state["ExitCode"])

    @staticmethod
    def _remove(container: Any) -> None:
        try:
            container.remove(force=True, v=True)
        except NotFound:
            pass
        except (DockerException, OSError) as error:
            # The reaper takes it within ten minutes.
            log.warning("sandbox_remove_failed", error=type(error).__name__)

    # -- the daemon, the image, the leftovers

    async def problem(self, image: str) -> str | None:
        """Why nothing can run now, or None when something can: the daemon, the runtime and the
        image are checked. The text is for the log and for an operator."""
        return await anyio.to_thread.run_sync(self._problem, image)

    def _problem(self, image: str) -> str | None:
        try:
            client = self.docker()
            info = client.info()
        except SandboxUnavailable as error:
            return str(error)
        except (DockerException, OSError) as error:
            return f"the Docker daemon cannot be reached ({type(error).__name__})"
        runtimes = info.get("Runtimes") or {}
        if self._runtime not in runtimes:
            return f"the Docker daemon has no runtime {self._runtime!r} (it has {sorted(runtimes)})"
        try:
            client.images.get(image)
        except ImageNotFound:
            return f"the image {image} is not built"
        except (DockerException, OSError) as error:
            return f"the image {image} cannot be inspected ({type(error).__name__})"
        return None

    async def reap(self, max_age_s: float = REAP_AFTER_S) -> int:
        """Remove the sandbox containers older than `max_age_s`, running or not: a run lasts
        seconds, so one this old is a leftover of a process that died. Only containers with the
        label are looked at. Returns how many were removed."""
        return await anyio.to_thread.run_sync(self._reap, max_age_s)

    def _reap(self, max_age_s: float) -> int:
        client = self.docker()
        now = self._clock()
        removed = 0
        # The low-level listing. The model's `list` inspects each container after it has listed it,
        # and a run that removes its own container in between fails the whole round with NotFound.
        for found in client.api.containers(all=True, filters={"label": f"{SANDBOX_LABEL}=1"}):
            created = _created_at(found)
            if created is not None and now - created < max_age_s:
                continue
            try:
                client.api.remove_container(found["Id"], force=True, v=True)
                removed += 1
                log.warning("sandbox_container_reaped", container=str(found["Id"])[:12])
            except NotFound:
                pass  # a run finished and removed it first
            except (DockerException, OSError) as error:
                log.warning("sandbox_reap_failed", error=type(error).__name__)
        return removed

    async def run_reaper(
        self, interval_s: float = REAP_EVERY_S, max_age_s: float = REAP_AFTER_S
    ) -> None:
        """Reap now and then every `interval_s`, for ever. Cancel it to stop. A failure is logged
        and tried again at the next round: a daemon that is away must not end the task."""
        while True:
            try:
                await self.reap(max_age_s)
            except Exception as error:
                log.warning("sandbox_reaper_failed", error=type(error).__name__)
            await anyio.sleep(interval_s)


def _why(error: BaseException) -> str:
    """The part of a Docker error that helps an operator. Not shown to the agent."""
    if isinstance(error, APIError):
        return f"{type(error).__name__}: {error.explanation or error}"[:300]
    return type(error).__name__


def _feed(sock: socket.socket, data: bytes) -> None:
    """Write the input and close the write side, so the script sees the end of its stdin. The
    thread ends with an error when the container is killed and the socket closed."""
    try:
        sock.settimeout(None)
        sock.sendall(data)
        sock.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def _close(sock: Any) -> None:
    with contextlib.suppress(OSError):
        sock.close()
