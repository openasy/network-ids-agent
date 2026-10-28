import { appendFileSync, mkdtempSync, renameSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { readBatch, strip } from "./eve.ts";

const line = (o: Record<string, unknown>) => JSON.stringify({ timestamp: "2026-10-28T13:58:12.114231+0000", ...o }) + "\n";
const alert = (sid: number) =>
  line({ event_type: "alert", src_ip: "192.0.2.17", dest_ip: "203.0.113.53", alert: { signature_id: sid }, payload: "c2VjcmV0", packet: "AAAA" });

function eve() {
  const dir = mkdtempSync(join(tmpdir(), "nids-eve-"));
  const path = join(dir, "eve.json");
  writeFileSync(path, "");
  return path;
}

describe("eve.json", () => {
  it("is read in whole lines from where it stopped, without payloads or other event types", async () => {
    const path = eve();
    appendFileSync(path, alert(1) + line({ event_type: "fileinfo" }) + "not json\n" + line({ event_type: "flow", flow: {} }));
    const first = await readBatch(path, undefined);
    expect(first.events.map((e) => e.event_type)).toEqual(["alert", "flow"]);
    expect(first.events[0]).not.toHaveProperty("payload");
    expect(first.events[0]).not.toHaveProperty("packet");
    expect(first.skipped).toBe(2);
    // A line Suricata is still writing waits for its end.
    appendFileSync(path, alert(2) + '{"event_type":"alert","src');
    const second = await readBatch(path, first.next);
    expect(second.events.map((e) => (e.alert as { signature_id: number }).signature_id)).toEqual([2]);
    appendFileSync(path, '_ip":"192.0.2.1","dest_ip":"192.0.2.2","alert":{"signature_id":3}}\n');
    expect((await readBatch(path, second.next)).events).toHaveLength(1);
  });

  it("starts again at the beginning of a new file after rotation", async () => {
    const path = eve();
    appendFileSync(path, alert(1) + alert(2));
    const first = await readBatch(path, undefined);
    renameSync(path, `${path}.1`);
    writeFileSync(path, alert(3));
    const after = await readBatch(path, first.next);
    expect(after.events.map((e) => (e.alert as { signature_id: number }).signature_id)).toEqual([3]);
  });

  it("is read in batches when much waits, and skips a line too long to be an event", async () => {
    const path = eve();
    appendFileSync(path, Array.from({ length: 12 }, (_, i) => alert(i)).join(""));
    const b = await readBatch(path, undefined, { maxEvents: 5 });
    expect(b.events).toHaveLength(5);
    expect(b.more).toBe(true);
    const long = eve();
    appendFileSync(long, `{"event_type":"alert","x":"${"a".repeat(2 * 1024 * 1024)}"}\n` + alert(9));
    const r = await readBatch(long, undefined, { maxBytes: 1024 * 1024 });
    expect(r.events).toHaveLength(1);
    expect(r.skipped).toBe(1);
  });

  it("leaves HTTP bodies on the sensor", () => {
    expect(strip({ event_type: "http", http: { hostname: "x", http_response_body: "secret" } })).toEqual({ event_type: "http", http: { hostname: "x" } });
  });
});
