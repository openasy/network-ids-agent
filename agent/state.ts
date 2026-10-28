// What the agent keeps on its own volume (ADR 0021): the secret it got when it enrolled, where it stopped in
// eve.json, and the hash of the rules it last wrote, sealed with its own key-encryption key.
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { Keyring } from "./kek.ts";

export interface AgentState {
  /** Set once enrolled: who this agent is to Network IDS. */
  sensorId?: string;
  name?: string;
  secret?: string;
  /** The file eve.json was when last read, by inode, and the byte after the last whole line sent. */
  eve?: { ino: number; offset: number };
  /** The hash of the rules and suppressions last written and loaded. */
  configHash?: string;
}

export function loadState(path: string, keyring: Keyring): AgentState {
  let sealed: string | undefined;
  try {
    sealed = readFileSync(path, "utf8").trim();
  } catch {
    sealed = undefined;
  }
  return sealed ? (JSON.parse(keyring.open(sealed).toString("utf8")) as AgentState) : {};
}

export function saveState(path: string, keyring: Keyring, state: AgentState) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, keyring.seal(JSON.stringify(state)), { mode: 0o600 });
  renameSync(tmp, path);
}
