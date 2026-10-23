import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

/** The repository root, where compose, `.env` and the scripts are. */
export const ROOT = path.resolve(import.meta.dirname, "../../..");

/** NAME=value lines, as `scripts/dev_env.sh` reads them: no quotes removed, nothing evaluated. */
function readLines(file: string): Record<string, string> {
  const values: Record<string, string> = {};
  if (!existsSync(file)) return values;
  for (const line of readFileSync(file, "utf8").split("\n")) {
    const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (match?.[1] !== undefined && match[2] !== undefined) values[match[1]] = match[2];
  }
  return values;
}

/**
 * The development settings, in the order of `scripts/dev_env.sh`: the environment first, then
 * `.env`, then `.env.example`. The passwords of the realm's people and the host ports are in them.
 * They are public values of the local stack, and the test uses them only against it.
 */
export function devEnv(): Record<string, string> {
  const fromProcess: Record<string, string> = {};
  for (const [name, value] of Object.entries(process.env)) {
    if (value !== undefined) fromProcess[name] = value;
  }
  return {
    ...readLines(path.join(ROOT, ".env.example")),
    ...readLines(path.join(ROOT, ".env")),
    ...fromProcess,
  };
}

export function ports(env: Record<string, string> = devEnv()) {
  return {
    keystone: Number(env["KEYSTONE_PORT"] ?? 8080),
    keycloak: Number(env["KEYCLOAK_PORT"] ?? 8180),
    bank: Number(env["BANK_PORT"] ?? 8103),
  };
}

export function urls(env: Record<string, string> = devEnv()) {
  const p = ports(env);
  return {
    keystone: `http://localhost:${p.keystone}`,
    realm: `http://localhost:${p.keycloak}/realms/keystone`,
    bank: `http://localhost:${p.bank}`,
  };
}
