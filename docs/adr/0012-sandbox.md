# ADR-0012: The sandbox is a Docker container with every flag turned on

Status: accepted
Date: 2026-10-23

## Context

An agent that can write code needs somewhere to run it. In the Keystone process a script reads the
master key and the database URL. As a child process it shares the host's network and files. Each
call has to run apart from every other call, from the host and from Keystone's own secrets.

Keystone already runs on Docker for local work, and a container with the right flags is a boundary
that holds for scripts a model wrote. It does not hold for hostile code from many tenants. This
ADR says what the flags are, where the line is, and what the design gives up.

## Decision

**One call is one container.** It is created, started, read until it ends or its time is up, and
removed. Nothing is reused, so a script cannot leave a file, a process or a socket for the next
one. `SandboxRunner.run(image, cmd, stdin, timeout_s)` in `src/keystone/sandbox/runner.py` does it
and returns the output, the exit code, and whether the run timed out or was cut short.

**The flags.** They are in one function (`container_config`), they are not settings, and a test
reads each of them back from the Docker API on a running container
(`tests/integration/test_sandbox_runner.py`).

| Flag | Value | What it stops |
|---|---|---|
| `network_mode` | `none` | any connection: there is a loopback and no route, so a script cannot reach the internet, Keystone, Postgres or another container |
| `read_only` | true | writing to the image: no changed binaries, no files in `/etc` |
| `tmpfs` | `/tmp` 64 MB without exec, `/workspace` 64 MB | writing anywhere else; what a script writes is memory, and is gone with the container |
| `mem_limit`, `memswap_limit` | 512 MB, the same | memory without end; with no swap the kernel kills the script when it passes the limit (exit code 137) |
| `nano_cpus` | 1 CPU | taking the host's processors |
| `pids_limit` | 128 | a fork bomb |
| `cap_drop` | `ALL` | every Linux capability: no raw sockets, no `chown`, no mounts |
| `security_opt` | `no-new-privileges` | a setuid binary raising its own rights |
| `user` | `10001:10001` | running as root; the user owns nothing in the image |
| `runtime` | `runc`, or `runsc` | with `runsc` (gVisor) a second kernel stands between the script and the host's |
| `privileged` | false | all of the above, in one flag |
| `log_config` | `none` | a copy of the output in a file on the host |
| labels | `keystone.sandbox=1`, `keystone.call_id=<id>` | losing track: the reaper and `docker ps` read them |

The image is `deploy/sandbox/Dockerfile.python`: Python 3.12 with numpy and pandas, `wget`, and the
user above. It is not part of the defense. It is small enough to start in under a second.

**Nothing crosses by path.** Keystone runs in a container when it runs under compose, so a path in
the Keystone process is not a path on the host that the daemon sees. A bind mount of a directory
of Keystone's would mount a directory of the host's, or none. So the code goes in as an argument
(`python -c`), the input goes in on standard input, and the output comes back on the attach stream.
The only filesystems are the image and two tmpfs.

**Output is capped, and a flood is cut off.** stdout and stderr each keep their first 64 KB and the
result says `truncated`. A script that writes 32 MB is killed, because reading without end keeps a
thread busy. The kill is made from a second thread while the first goes on reading: the daemon does
not report a container as stopped until everything it wrote has been copied out, and the first
version of this code, which stopped reading to kill, waited out its own 30 second timeout.

**Time.** A run that is still going at `timeout_s` (30 s by default, at most 300) is killed and
says `timed_out`. The tool's own timeout is ten seconds longer, so that a timed-out run is a result
the agent can read and not a failed call.

**Leftovers.** A reaper task removes any container with the label that is older than 10 minutes,
every 60 seconds, running or not. A run lasts seconds, so one that old belongs to a process that
died. It looks at nothing without the label.

**The Docker socket.** Keystone reaches the daemon through `/var/run/docker.sock`, which compose
mounts into the Keystone container. Whoever can use that socket can start any container on the
host as root, so a compromised Keystone owns the machine it runs on. This is acceptable for a
laptop and for one host that runs nothing else you care about, and it is why the compose file says
"local and single-host use only" next to the mount. Keystone runs as user 10001, which the socket
(owned by root on Docker Desktop) does not let in; compose adds the socket's group
(`DOCKER_SOCKET_GID`, default 0).

**Where the sandbox is not available.** A Fargate task has no Docker daemon. There
`KEYSTONE_SANDBOX_ENABLED=false`, and the `sandbox` upstream is not registered, so no tool is
listed and nothing talks to Docker. The AWS deployment in Phase 9 sets it.

## Consequences

- A run costs about what starting a container costs. On this machine (Docker Desktop, runc, 30 runs
  after a warm-up) `print(2+2)` took a median of 381 ms and a p95 of 483 ms from the call to the
  result, and a script that imports numpy and pandas a median of 974 ms and a p95 of 1,181 ms.
  The first is the cost of a container and the difference between the two is the import. Code
  execution is the slowest tool Keystone serves.
- At most `sandbox.max_concurrent` (4) containers run at once. A call over that waits for one to
  end, inside the tool's own timeout. 4 containers of 512 MB fit in the 8 GB that Docker Desktop
  has here.
- The memory limit includes the tmpfs. A script that fills `/workspace` with 64 MB has 448 MB left.
- A container shares the host's kernel. A kernel bug that escapes a container escapes this one.
  The flags make that harder and not impossible: no capabilities, a seccomp profile (Docker's
  default), no network and a read-only root leave little to start from. For code from tenants who
  do not trust each other, set `sandbox.runtime: runsc` on a host that has gVisor, or put the
  sandbox on a machine of its own with a microVM runtime (Firecracker). Keystone does not ship
  either, and does not claim this design is enough for that case.
- Every run is a create, a start and a remove on the daemon, and a flood of them costs the daemon
  CPU however small each script is. The rate limit (KS-804) is what stops an agent from asking
  for that many.
- Everything a script prints reaches the agent through the output scanner like any tool's result.
  The sandbox does not make its output trusted: a script can print an instruction.

## Revisit when

A deployment needs the sandbox on Fargate or Kubernetes, where there is no Docker socket: that is
a runner of its own (a job per call), behind the same `SandboxRunner` interface. Or when a
tenant's code must run next to another tenant's: gVisor or a microVM becomes a requirement and not
a switch.
