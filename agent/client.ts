// Everything the agent sends goes to the Network IDS API, and only that way (ADR 0018, 0023): the agent accepts no
// requests from Network IDS. It asks for the rules to write and sends what Suricata saw.
import { gzipSync } from "node:zlib";

export interface Report {
  version: string;
  hostname: string;
  evePath: string;
  configHash: string | null;
  configError: string | null;
}

export interface Config {
  hash: string;
  rules: string[];
  suppressions: string[];
}

export class IdsError extends Error {
  readonly status: number | undefined;
  readonly code: string | undefined;
  constructor(status: number | undefined, code: string | undefined, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function call<T>(url: string, path: string, init: { secret?: string; body: unknown; timeoutMs?: number }): Promise<T> {
  let res: Response;
  try {
    res = await fetch(new URL(path, url), {
      method: "POST",
      headers: { ...(init.secret && { authorization: `Bearer ${init.secret}` }), "content-type": "application/json", "content-encoding": "gzip" },
      body: gzipSync(JSON.stringify(init.body)),
      signal: AbortSignal.timeout(init.timeoutMs ?? 15_000),
    });
  } catch (err) {
    throw new IdsError(undefined, "unreachable", `network-ids at ${url} is unreachable: ${(err as Error).message}`);
  }
  if (!res.ok) {
    const p = (await res.json().catch(() => ({}))) as { code?: string; detail?: string; title?: string };
    throw new IdsError(res.status, p.code, p.detail ?? p.title ?? `${res.status}`);
  }
  return (await res.json()) as T;
}

export const enroll = (url: string, token: string, report: Report) =>
  call<{ sensorId: string; name: string; secret: string }>(url, "/api/v1/agent/enroll", { body: { token, ...report } });
export const config = (url: string, secret: string, report: Report) => call<Config>(url, "/api/v1/agent/config", { secret, body: report });
export const sendEvents = (url: string, secret: string, events: unknown[]) =>
  call<{ refused: number; refusals: string[] }>(url, "/api/v1/agent/events", { secret, body: { events }, timeoutMs: 60_000 });
