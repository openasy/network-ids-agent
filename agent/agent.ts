// The loop: write the rules Network IDS gives, then send what Suricata wrote since the last round. Network IDS being
// down never stops the agent; it says so in /readyz and keeps trying, and eve.json waits where it stopped (ADR 0023).
import { config, enroll, IdsError, sendEvents, type Report } from "./client.ts";
import { readBatch } from "./eve.ts";
import type { Keyring } from "./kek.ts";
import { log } from "./log.ts";
import { hashOf, render, writeFiles } from "./rules.ts";
import { saveState, type AgentState } from "./state.ts";
import { reloadRules } from "./suricata.ts";

export interface AgentOptions {
  url: string;
  version: string;
  hostname: string;
  state: AgentState;
  statePath: string;
  keyring: Keyring;
  enrollToken?: string;
  evePath: string;
  rulesDir: string;
  /** Suricata's command socket; without it, Suricata is not asked to reload. */
  socketPath?: string;
  /** Batches sent in one round at most, so the rules are looked at again in between. */
  maxBatches?: number;
  reload?: (socketPath: string) => Promise<void>;
}

export interface Status {
  enrolled: boolean;
  idsOk: boolean;
  lastError: string | null;
  lastContactAt: string | null;
  eventsSent: number;
  linesSkipped: number;
  reloads: number;
  configError: string | null;
}

export function createAgent(o: AgentOptions) {
  const status: Status = {
    enrolled: !!o.state.secret,
    idsOk: false,
    lastError: null,
    lastContactAt: null,
    eventsSent: 0,
    linesSkipped: 0,
    reloads: 0,
    configError: null,
  };
  const reload = o.reload ?? reloadRules;
  const report = (): Report => ({
    version: o.version,
    hostname: o.hostname,
    evePath: o.evePath,
    configHash: o.state.configHash ?? null,
    configError: status.configError,
  });
  const save = () => saveState(o.statePath, o.keyring, o.state);
  const failed = (err: unknown) => {
    status.idsOk = false;
    status.lastError = (err as Error).message;
    log("warn", "network-ids call failed", { status: (err as IdsError).status, error: status.lastError });
  };

  /** Enrols once with the one-time token; afterwards the agent has its own secret (ADR 0023). */
  async function ensureEnrolled(): Promise<boolean> {
    if (o.state.secret) return true;
    if (!o.enrollToken) {
      status.lastError = "Not enrolled: add this sensor in Network IDS under Sensors, and start the agent with NETWORK_IDS_ENROLL_TOKEN";
      return false;
    }
    try {
      const r = await enroll(o.url, o.enrollToken, report());
      o.state.sensorId = r.sensorId;
      o.state.name = r.name;
      o.state.secret = r.secret;
      save();
      status.enrolled = true;
      log("info", "enrolled", { sensor: r.name });
      return true;
    } catch (err) {
      failed(err);
      return false;
    }
  }

  /** Writes the rules and suppressions when they changed, and asks Suricata to reload them. */
  async function apply(c: { hash: string; rules: string[]; suppressions: string[] }) {
    if (c.hash === o.state.configHash && !status.configError) return;
    try {
      const files = render(c);
      // The hash is the agent's own, of what it checked, not the one it was told.
      const hash = hashOf(c);
      const changed = writeFiles(o.rulesDir, files);
      // Reloaded until it once worked for this hash, also when the files were already written: Suricata may not
      // have loaded them, if the last reload failed or the agent stopped before it.
      if (o.socketPath) {
        await reload(o.socketPath);
        status.reloads++;
      } else log("warn", "rules written; Suricata was not asked to reload (no SURICATA_SOCKET)");
      o.state.configHash = hash;
      status.configError = null;
      save();
      log("info", "rules written", { rules: c.rules.length, suppressions: c.suppressions.length, changed, reloaded: !!o.socketPath });
    } catch (err) {
      const error = (err as Error).message;
      // Tried again every round; said once until it changes.
      if (error !== status.configError) log("error", "rules not applied", { error });
      status.configError = error;
    }
  }

  /** One round: the rules first, then batches of events until none wait or maxBatches is reached. */
  async function round() {
    if (!(await ensureEnrolled())) return;
    try {
      const c = await config(o.url, o.state.secret!, report());
      status.idsOk = true;
      status.lastError = null;
      status.lastContactAt = new Date().toISOString();
      await apply(c);
    } catch (err) {
      failed(err);
      if ((err as IdsError).status === 401) log("error", "the agent's secret was refused: enrol it again under Sensors");
      return;
    }
    for (let i = 0; i < (o.maxBatches ?? 10); i++) {
      let batch;
      try {
        batch = await readBatch(o.evePath, o.state.eve);
      } catch (err) {
        status.lastError = `cannot read ${o.evePath}: ${(err as Error).message}`;
        log("warn", "eve.json not readable", { path: o.evePath, error: String(err) });
        return;
      }
      if (batch.events.length) {
        try {
          const r = await sendEvents(o.url, o.state.secret!, batch.events);
          if (r.refused) log("warn", "events refused", { refused: r.refused, reasons: r.refusals });
          status.eventsSent += batch.events.length;
        } catch (err) {
          failed(err);
          return;
        }
      }
      status.linesSkipped += batch.skipped;
      const moved = !o.state.eve || o.state.eve.ino !== batch.next.ino || o.state.eve.offset !== batch.next.offset;
      o.state.eve = batch.next;
      if (moved) save();
      if (!batch.more) return;
    }
  }

  return { round, status };
}
