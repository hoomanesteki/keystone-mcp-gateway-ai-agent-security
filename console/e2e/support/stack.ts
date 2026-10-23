import { execFileSync, spawn, spawnSync, type ChildProcess } from "node:child_process";
import { closeSync, existsSync, mkdirSync, openSync } from "node:fs";
import path from "node:path";
import { devEnv, ROOT, urls } from "./dev-env";

const SCRIPT = "examples/agents/scripts/approval_demo.yaml";

async function answers(url: string): Promise<boolean> {
  try {
    return (await fetch(url, { signal: AbortSignal.timeout(2500) })).ok;
  } catch {
    return false;
  }
}

/** Keystone ready, Keycloak serving the realm, and the bank up: what the test needs. */
export async function stackIsUp(): Promise<boolean> {
  const where = urls();
  const checks = await Promise.all([
    answers(`${where.keystone}/readyz`),
    answers(`${where.realm}/.well-known/openid-configuration`),
    answers(`${where.bank}/healthz`),
  ]);
  return checks.every(Boolean);
}

/** `make up`, for a run that finds nothing listening. It builds the images, so it can take
 * minutes the first time. */
export function startStack(): void {
  console.log("The compose stack is not up. Starting it (docker compose up --build --wait).");
  const env = existsSync(path.join(ROOT, ".env")) ? ["--env-file", ".env"] : [];
  const result = spawnSync(
    "docker",
    ["compose", "-f", "deploy/docker-compose.yml", ...env, "up", "-d", "--build", "--wait"],
    { cwd: ROOT, stdio: "inherit", timeout: 20 * 60_000 },
  );
  if (result.status !== 0) {
    throw new Error(
      `docker compose up failed (status ${String(result.status)}). Is Docker running?`,
    );
  }
}

/** The bank at its seed state, so its list of transfers holds only what this run makes. */
export async function resetBank(): Promise<void> {
  const response = await fetch(`${urls().bank}/_reset`, {
    method: "POST",
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error(`the bank did not reset: ${String(response.status)}`);
}

export interface Agent {
  child: ChildProcess;
  /** Where the agent writes its transcript, which it prints when its script has run. */
  transcript: string;
}

/**
 * Olivia's scripted agent (examples/agents/scripts/approval_demo.yaml: a transfer of 900, then the
 * await tool), in the background. Keystone holds the transfer for a person, so the agent is
 * waiting when the test signs in.
 */
export function startAgent(transcript: string): Agent {
  const token = execFileSync("bash", ["scripts/get_token.sh", "olivia", "ops-agent"], {
    cwd: ROOT,
    env: devEnv(),
    encoding: "utf8",
    timeout: 30_000,
  }).trim();
  mkdirSync(path.dirname(transcript), { recursive: true });
  const output = openSync(transcript, "w");
  const child = spawn(
    "uv",
    [
      "run",
      "python",
      "-m",
      "examples.agents.scripted_agent",
      "--url",
      `${urls().keystone}/mcp`,
      "--script",
      SCRIPT,
      "--format",
      "text",
    ],
    {
      cwd: ROOT,
      env: { ...process.env, KEYSTONE_TOKEN: token },
      stdio: ["ignore", output, output],
    },
  );
  closeSync(output);
  child.on("error", (error) => {
    console.error("The scripted agent could not start:", error.message);
  });
  return { child, transcript };
}
