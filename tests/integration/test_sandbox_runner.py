"""KS-801 against a real Docker daemon: the runner runs code in a locked-down container.

They need the image from deploy/sandbox/Dockerfile.python (`make sandbox-image`). Each test that
starts a container checks that it is gone afterwards (tests/fixtures/sandbox.py).
"""

import contextlib
import json
import textwrap
import time
from typing import Any

import anyio
import pytest
from docker.errors import ImageNotFound

from keystone.core.ids import new_id
from keystone.sandbox.runner import (
    CALL_LABEL,
    MAX_OUTPUT_BYTES,
    SANDBOX_LABEL,
    SandboxResult,
    SandboxRunner,
    SandboxUnavailable,
)
from tests.fixtures.sandbox import containers_of, wait_until

pytestmark = [pytest.mark.phase(8), pytest.mark.docker]

MEBIBYTE = 1024 * 1024


def python(code: str) -> list[str]:
    return ["python", "-c", textwrap.dedent(code)]


async def run_python(runner: SandboxRunner, image: str, code: str, **options: Any) -> SandboxResult:
    return await runner.run(image, python(code), **options)


async def test_runs_code_and_returns_output(runner: SandboxRunner, sandbox_image: str) -> None:
    result = await run_python(runner, sandbox_image, "print(2+2)")

    assert result.stdout == "4\n"
    assert (result.stderr, result.exit_code) == ("", 0)
    assert (result.timed_out, result.truncated) == (False, False)
    assert 0 < result.duration_ms < 10_000


async def test_stdout_and_stderr_are_kept_apart_and_the_exit_code_is_the_scripts(
    runner: SandboxRunner, sandbox_image: str
) -> None:
    result = await run_python(
        runner,
        sandbox_image,
        """
        import sys
        print("out")
        print("err", file=sys.stderr)
        sys.exit(3)
        """,
    )

    assert (result.stdout, result.stderr, result.exit_code) == ("out\n", "err\n", 3)


async def test_stdin_reaches_the_script_and_ends(runner: SandboxRunner, sandbox_image: str) -> None:
    result = await runner.run(
        sandbox_image,
        python("import sys; data = sys.stdin.read(); print(len(data), data[:3])"),
        stdin="abc" * 1000,
    )

    assert (result.stdout, result.exit_code) == ("3000 abc\n", 0)


async def test_numpy_and_pandas_are_in_the_image(runner: SandboxRunner, sandbox_image: str) -> None:
    result = await run_python(
        runner,
        sandbox_image,
        """
        import numpy as np, pandas as pd
        frame = pd.DataFrame({"a": np.arange(5)})
        print(int(frame["a"].sum()))
        """,
    )

    assert (result.stdout, result.exit_code) == ("10\n", 0)


async def test_no_network(runner: SandboxRunner, sandbox_image: str) -> None:
    result = await run_python(
        runner,
        sandbox_image,
        """
        import socket
        socket.create_connection(("1.1.1.1", 80), timeout=3)
        """,
    )

    assert result.exit_code != 0
    assert "Network is unreachable" in result.stderr
    routes = await run_python(
        runner, sandbox_image, "print(len(open('/proc/net/route').read().splitlines()))"
    )
    # Only the header line: the container has no route anywhere.
    assert routes.stdout == "1\n"


async def test_a_name_cannot_be_resolved(runner: SandboxRunner, sandbox_image: str) -> None:
    result = await runner.run(sandbox_image, ["wget", "-T", "3", "http://example.com"])

    assert result.exit_code != 0
    assert "unable to resolve" in result.stderr


async def test_timeout_kills(runner: SandboxRunner, sandbox_image: str, docker_client: Any) -> None:
    call_id = new_id()
    started = time.monotonic()

    result = await run_python(
        runner, sandbox_image, "while True: pass", timeout_s=2, call_id=call_id
    )

    assert result.timed_out is True
    assert result.exit_code == 137  # SIGKILL
    assert 1.8 <= time.monotonic() - started < 10
    assert containers_of(docker_client, call_id) == []


async def test_memory_limit(runner: SandboxRunner, sandbox_image: str) -> None:
    # A bytes object is filled with the byte, so every page is touched. A bytearray of zeros is
    # not: the kernel hands out pages that nobody has written to, and they cost nothing.
    result = await run_python(runner, sandbox_image, "data = b'x' * (1024 ** 3); print(len(data))")

    assert result.exit_code != 0
    assert result.exit_code == 137  # the kernel's OOM killer
    assert result.timed_out is False
    assert result.stdout == ""


async def test_readonly_root(runner: SandboxRunner, sandbox_image: str) -> None:
    result = await run_python(runner, sandbox_image, "open('/etc/x', 'w').write('1')")

    assert result.exit_code != 0
    assert "Read-only file system" in result.stderr


async def test_only_the_tmpfs_directories_are_writable(
    runner: SandboxRunner, sandbox_image: str
) -> None:
    result = await run_python(
        runner,
        sandbox_image,
        """
        import os, subprocess
        for path in ("/tmp/a", "/workspace/b"):
            with open(path, "w") as handle:
                handle.write("x")
            print(path, "written")
        # The tmpfs mounts do not execute anything: a copy of a program cannot be started.
        with open("/bin/true", "rb") as source, open("/tmp/true", "wb") as copy:
            copy.write(source.read())
        os.chmod("/tmp/true", 0o755)
        try:
            subprocess.run(["/tmp/true"], check=True)
        except PermissionError:
            print("exec refused")
        """,
    )

    assert result.stdout.splitlines() == [
        "/tmp/a written",  # noqa: S108 - inside the container
        "/workspace/b written",
        "exec refused",
    ]


async def test_output_truncated(runner: SandboxRunner, sandbox_image: str) -> None:
    result = await run_python(runner, sandbox_image, "print('x' * 1_000_000)")

    assert result.truncated is True
    assert len(result.stdout.encode()) == MAX_OUTPUT_BYTES == 64 * 1024
    assert result.exit_code == 0


async def test_stderr_is_capped_on_its_own(runner: SandboxRunner, sandbox_image: str) -> None:
    result = await run_python(
        runner,
        sandbox_image,
        """
        import sys
        sys.stderr.write("e" * 200_000)
        print("fine")
        """,
    )

    assert (result.stdout, result.truncated) == ("fine\n", True)
    assert len(result.stderr.encode()) == MAX_OUTPUT_BYTES


async def test_output_exactly_at_the_cap_is_not_truncated(
    runner: SandboxRunner, sandbox_image: str
) -> None:
    result = await run_python(runner, sandbox_image, f"print('x' * {MAX_OUTPUT_BYTES - 1})")

    assert (len(result.stdout.encode()), result.truncated) == (MAX_OUTPUT_BYTES, False)


async def test_output_that_never_stops_is_cut_off(
    runner: SandboxRunner, sandbox_image: str
) -> None:
    result = await run_python(
        runner,
        sandbox_image,
        """
        import sys
        block = "y" * 65536
        while True:
            sys.stdout.write(block)
        """,
        timeout_s=20,
    )

    # Killed for the output (32 MB) and not for the time, well inside the 20 seconds.
    assert result.truncated is True
    assert result.timed_out is False
    assert result.duration_ms < 15_000


async def test_the_process_limit_holds(runner: SandboxRunner, sandbox_image: str) -> None:
    result = await run_python(
        runner,
        sandbox_image,
        """
        import subprocess
        children = []
        try:
            while True:
                children.append(subprocess.Popen(["sleep", "30"]))
        except OSError as error:
            print(len(children), error.errno)
        for child in children:
            child.kill()
        """,
        timeout_s=20,
    )

    count, errno = result.stdout.split()
    # 128 processes, the script among them. EAGAIN is 11.
    assert 100 <= int(count) < 128
    assert errno == "11"


async def test_limits_hold_inside_the_container(runner: SandboxRunner, sandbox_image: str) -> None:
    result = await run_python(
        runner,
        sandbox_image,
        """
        import json, os

        def first(path):
            with open(path) as handle:
                return handle.read().split()

        lines = open("/proc/self/status").read().splitlines()
        status = dict(line.split(":", 1) for line in lines if ":" in line)
        print(json.dumps({
            "uid": os.getuid(),
            "gid": os.getgid(),
            "cap_eff": status["CapEff"].strip(),
            "no_new_privs": status["NoNewPrivs"].strip(),
            "memory_max": first("/sys/fs/cgroup/memory.max")[0],
            "swap_max": first("/sys/fs/cgroup/memory.swap.max")[0],
            "pids_max": first("/sys/fs/cgroup/pids.max")[0],
            "cpu_max": first("/sys/fs/cgroup/cpu.max"),
            "cwd": os.getcwd(),
            "env": sorted(k for k in os.environ if k.startswith("KEYSTONE")),
        }))
        """,
    )

    assert result.exit_code == 0, result.stderr
    seen = json.loads(result.stdout)
    assert seen == {
        "uid": 10001,
        "gid": 10001,
        "cap_eff": "0000000000000000",
        "no_new_privs": "1",
        "memory_max": str(512 * MEBIBYTE),
        "swap_max": "0",
        "pids_max": "128",
        "cpu_max": ["100000", "100000"],
        "cwd": "/workspace",
        "env": [],
    }


async def test_every_hardening_flag_is_set_on_the_container(
    runner: SandboxRunner, sandbox_image: str, docker_client: Any
) -> None:
    """The phase gate: read the configuration of a container that is running, from the Docker
    API, and compare each flag. The runner is not asked what it meant to set."""
    call_id = new_id()
    async with anyio.create_task_group() as group:
        group.start_soon(
            lambda: runner.run(sandbox_image, ["sleep", "20"], timeout_s=20, call_id=call_id)
        )
        found = await anyio.to_thread.run_sync(
            lambda: wait_until(lambda: containers_of(docker_client, call_id))
        )
        assert found, "the container never appeared"
        [container] = found
        info = docker_client.api.inspect_container(container.id)
        container.kill()

    host, config = info["HostConfig"], info["Config"]
    flags = {
        "network_mode=none": host["NetworkMode"],
        "read_only=True": host["ReadonlyRootfs"],
        "tmpfs": host["Tmpfs"],
        "mem_limit=512m": host["Memory"],
        "memswap_limit=512m": host["MemorySwap"],
        "nano_cpus=1e9": host["NanoCpus"],
        "pids_limit=128": host["PidsLimit"],
        "cap_drop=ALL": host["CapDrop"],
        "cap_add": host["CapAdd"] or [],
        "security_opt": host["SecurityOpt"],
        "privileged": host["Privileged"],
        "user=10001:10001": config["User"],
        "runtime=runc": host["Runtime"],
        "label keystone.sandbox": config["Labels"].get(SANDBOX_LABEL),
        "label keystone.call_id": config["Labels"].get(CALL_LABEL),
        "log driver none": host["LogConfig"]["Type"],
        "working_dir": config["WorkingDir"],
        "tty": config["Tty"],
        # The daemon on Linux answers null where Docker Desktop answers an empty list or map.
        "ports": host["PortBindings"] or {},
        "devices": host["Devices"] or [],
        "volumes": host["Binds"] or [],
        "mounts other than tmpfs": [m for m in info["Mounts"] if m["Type"] != "tmpfs"],
        "pid_mode": host["PidMode"],
        "ipc_mode": host["IpcMode"],
    }
    expected = {
        "network_mode=none": "none",
        "read_only=True": True,
        "tmpfs": {"/tmp": "size=64m,noexec", "/workspace": "size=64m"},  # noqa: S108
        "mem_limit=512m": 512 * MEBIBYTE,
        "memswap_limit=512m": 512 * MEBIBYTE,
        "nano_cpus=1e9": 1_000_000_000,
        "pids_limit=128": 128,
        "cap_drop=ALL": ["ALL"],
        "cap_add": [],
        "security_opt": ["no-new-privileges"],
        "privileged": False,
        "user=10001:10001": "10001:10001",
        "runtime=runc": "runc",
        "label keystone.sandbox": "1",
        "label keystone.call_id": call_id,
        "log driver none": "none",
        "working_dir": "/workspace",
        "tty": False,
        "ports": {},
        "devices": [],
        "volumes": [],
        "mounts other than tmpfs": [],
        "pid_mode": "",
        "ipc_mode": "private",
    }
    assert {k: v for k, v in flags.items() if v != expected[k]} == {}
    assert flags.keys() == expected.keys()
    # The environment holds what the image sets and nothing of Keystone's.
    assert not [e for e in config["Env"] if e.upper().startswith("KEYSTONE")]


async def test_the_container_is_gone_after_every_kind_of_end(
    runner: SandboxRunner, sandbox_image: str, docker_client: Any
) -> None:
    ends = {
        "normal": "print(1)",
        "error": "raise SystemExit(2)",
        "crash": "import os; os.kill(os.getpid(), 9)",
    }
    for name, code in ends.items():
        call_id = new_id()
        await run_python(runner, sandbox_image, code, call_id=call_id)
        assert containers_of(docker_client, call_id) == [], name


async def test_a_cancelled_run_is_killed_and_removed(
    runner: SandboxRunner, sandbox_image: str, docker_client: Any
) -> None:
    call_id = new_id()
    async with anyio.create_task_group() as group:
        group.start_soon(
            lambda: runner.run(sandbox_image, ["sleep", "60"], timeout_s=60, call_id=call_id)
        )
        appeared = await anyio.to_thread.run_sync(
            lambda: wait_until(lambda: containers_of(docker_client, call_id))
        )
        assert appeared
        group.cancel_scope.cancel()

    # The thread sees the event within a fraction of a second, kills the container and removes it.
    gone = await anyio.to_thread.run_sync(
        lambda: wait_until(lambda: not containers_of(docker_client, call_id), 15)
    )
    assert gone


async def test_runs_are_limited_to_max_concurrent(docker_client: Any, sandbox_image: str) -> None:
    runner = SandboxRunner(docker_client, max_concurrent=2)
    started = time.monotonic()

    async with anyio.create_task_group() as group:
        for _ in range(4):
            group.start_soon(runner.run, sandbox_image, ["sleep", "1"])

    # Four runs of a second, two at a time: two rounds, never fewer.
    assert time.monotonic() - started >= 2.0


async def test_a_missing_image_is_unavailable_and_is_not_pulled(
    runner: SandboxRunner, docker_client: Any
) -> None:
    name = "keystone-no-such-image:0"

    with pytest.raises(SandboxUnavailable, match="is not built"):
        await runner.run(name, ["true"])

    with pytest.raises(ImageNotFound):
        docker_client.images.get(name)


async def test_problem_names_what_is_wrong(
    runner: SandboxRunner, sandbox_image: str, docker_client: Any
) -> None:
    assert await runner.problem(sandbox_image) is None
    assert "is not built" in (await runner.problem("keystone-no-such-image:0") or "")
    gvisor = SandboxRunner(docker_client, runtime="runsc-not-installed")
    assert "no runtime 'runsc-not-installed'" in (await gvisor.problem(sandbox_image) or "")


async def test_reaper_removes_stale(
    runner: SandboxRunner, sandbox_image: str, docker_client: Any
) -> None:
    stale = docker_client.containers.create(
        sandbox_image, ["sleep", "300"], labels={SANDBOX_LABEL: "1"}
    )
    other = docker_client.containers.create(sandbox_image, ["sleep", "300"])
    try:
        # Made a moment ago, so ten minutes is not enough to reap it.
        assert await runner.reap(max_age_s=600) == 0
        assert {c["Id"] for c in docker_client.api.containers(all=True)} >= {stale.id, other.id}

        removed = await runner.reap(max_age_s=0)

        assert removed == 1
        ids = {c["Id"] for c in docker_client.api.containers(all=True)}
        assert stale.id not in ids
        # Only containers with the label are touched.
        assert other.id in ids
    finally:
        other.remove(force=True)
        with contextlib.suppress(Exception):  # the reaper has removed it already
            stale.remove(force=True)


async def test_reaper_removes_a_running_container_that_is_old_enough(
    runner: SandboxRunner, sandbox_image: str, docker_client: Any
) -> None:
    survivor = docker_client.containers.run(
        sandbox_image, ["sleep", "300"], detach=True, labels={SANDBOX_LABEL: "1"}
    )

    assert await runner.reap(max_age_s=0) == 1
    assert not docker_client.api.containers(all=True, filters={"id": survivor.id})
