// Reads Suricata's eve.json from where the last batch stopped (ADR 0070). Only whole lines are read; the position
// moves on only once a batch is sent, so nothing is lost when Network IDS is down, and a batch sent twice counts once
// there. When Suricata starts a new file (logrotate, or a restart that truncates it), reading starts at its beginning.
import { open, stat } from "node:fs/promises";

/** The event types sent; the rest of what Suricata writes (fileinfo, anomaly, netflow...) stays on the sensor. */
export const EVENT_TYPES = new Set(["alert", "flow", "dns", "http", "tls", "ssh", "stats"]);
/** Fields with packet contents, which never leave the sensor. */
const PAYLOAD_FIELDS = ["payload", "payload_printable", "packet", "packet_info", "rule"];
const HTTP_BODIES = ["http_request_body", "http_request_body_printable", "http_response_body", "http_response_body_printable"];
/** A line longer than this is not an event Network IDS keeps; it is skipped. */
const MAX_LINE = 1024 * 1024;

export interface Position {
  ino: number;
  offset: number;
}

export interface Batch {
  events: Record<string, unknown>[];
  /** Where the next read starts, once this batch is sent. */
  next: Position;
  /** Lines that were not JSON objects, too long, or of another event type. */
  skipped: number;
  /** Whether more whole lines wait after this batch. */
  more: boolean;
}

/** The event as sent: without packet payloads, nor the rule text Suricata can add to an alert. */
export function strip(e: Record<string, unknown>): Record<string, unknown> {
  const out = { ...e };
  for (const f of PAYLOAD_FIELDS) delete out[f];
  if (out.http && typeof out.http === "object") {
    const http = { ...(out.http as Record<string, unknown>) };
    for (const f of HTTP_BODIES) delete http[f];
    out.http = http;
  }
  return out;
}

export async function readBatch(path: string, from: Position | undefined, o: { maxBytes?: number; maxEvents?: number } = {}): Promise<Batch> {
  const maxBytes = o.maxBytes ?? 4 * 1024 * 1024;
  const maxEvents = o.maxEvents ?? 5000;
  const st = await stat(path);
  // A new file, or the same one truncated: start at its beginning.
  let offset = from && from.ino === st.ino && from.offset <= st.size ? from.offset : 0;
  const events: Record<string, unknown>[] = [];
  let skipped = 0;
  const file = await open(path, "r");
  try {
    while (events.length < maxEvents && offset < st.size) {
      const length = Math.min(maxBytes, st.size - offset);
      const buf = Buffer.alloc(length);
      const { bytesRead } = await file.read(buf, 0, length, offset);
      const chunk = buf.subarray(0, bytesRead);
      let start = 0;
      let consumed = false;
      for (let nl = chunk.indexOf(10, start); nl >= 0 && events.length < maxEvents; nl = chunk.indexOf(10, start)) {
        const line = chunk.subarray(start, nl).toString("utf8").trim();
        start = nl + 1;
        consumed = true;
        if (!line) continue;
        try {
          const e = JSON.parse(line) as unknown;
          if (e && typeof e === "object" && !Array.isArray(e) && EVENT_TYPES.has((e as { event_type?: string }).event_type ?? ""))
            events.push(strip(e as Record<string, unknown>));
          else skipped++;
        } catch {
          skipped++;
        }
      }
      if (!consumed) {
        // No whole line in the chunk: Suricata is still writing it, or it is too long to be an event.
        if (bytesRead < MAX_LINE && offset + bytesRead >= st.size) break;
        const nl = await findNewline(file, offset + bytesRead, st.size);
        if (nl < 0) break;
        offset = nl + 1;
        skipped++;
        continue;
      }
      offset += start;
      if (bytesRead < length) break;
    }
  } finally {
    await file.close();
  }
  return { events, next: { ino: st.ino, offset }, skipped, more: offset < st.size && events.length >= maxEvents };
}

async function findNewline(file: Awaited<ReturnType<typeof open>>, from: number, size: number): Promise<number> {
  const buf = Buffer.alloc(64 * 1024);
  for (let at = from; at < size; at += buf.length) {
    const { bytesRead } = await file.read(buf, 0, buf.length, at);
    const i = buf.subarray(0, bytesRead).indexOf(10);
    if (i >= 0) return at + i;
  }
  return -1;
}
