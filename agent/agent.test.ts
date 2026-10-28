import { appendFileSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer as createHttp } from "node:http";
import { createServer as createNet } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createAgent } from "./agent.ts";
import { createAgentHandler } from "./app.ts";
import { createKeyring } from "./kek.ts";
import { hashOf } from "./rules.ts";
import { loadState } from "./state.ts";
import { reloadRules } from "./suricata.ts";

const RULE = 'alert http any any -> any any (msg:"LOCAL Admin path probe"; http.uri; content:"/admin"; sid:9000104; rev:1;)';

/** Network IDS as the agent sees it: enrolment, config and events, with what it was sent. */
async function fakeIds() {
  const calls: Array<{ path: string; auth: string | undefined; body: any }> = [];
  let config = { rules: [RULE], suppressions: ["suppress gen_id 1, sig_id 2013028"] };
  let down = false;
  const server = createHttp(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = JSON.parse(gunzipSync(Buffer.concat(chunks)).toString("utf8"));
    calls.push({ path: req.url ?? "", auth: req.headers.authorization, body });
    const json = (status: number, b: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(b));
    if (down) return json(503, { code: "internal-error", detail: "down" });
    if (req.url === "/api/v1/agent/enroll")
      return body.token === "oie_good"
        ? json(200, { sensorId: "s1", name: "nids-core-01", secret: "oia_secret" })
        : json(401, { code: "invalid-token", detail: "unknown token" });
    if (req.headers.authorization !== "Bearer oia_secret") return json(401, { code: "invalid-token", detail: "unknown secret" });
    if (req.url === "/api/v1/agent/config") return json(200, { hash: hashOf(config), ...config });
    if (req.url === "/api/v1/agent/events") return json(200, { refused: 0, refusals: [] });
    json(404, {});
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as { port: number };
  return {
    url: `http://127.0.0.1:${port}`,
    calls,
    set: (c: typeof config) => (config = c),
    down: (d: boolean) => (down = d),
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

/** Suricata's command socket, answering as Suricata 7 does. */
async function fakeSuricata(path: string, answer = { return: "OK", message: "done" }) {
  const received: unknown[] = [];
  const server = createNet((sock) => {
    sock.on("data", (d) => {
      const m = JSON.parse(d.toString("utf8")) as { version?: string; command?: string };
      received.push(m);
      sock.write(JSON.stringify(m.version ? { return: "OK" } : answer));
    });
  });
  await new Promise<void>((r) => server.listen(path, r));
  return { received, close: () => new Promise<void>((r) => server.close(() => r())) };
}

let dir: string;
let ids: Awaited<ReturnType<typeof fakeIds>>;
const keyring = createKeyring(Buffer.alloc(32, 7));

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "nids-agent-"));
  writeFileSync(join(dir, "eve.json"), "");
  ids = await fakeIds();
});
afterEach(() => ids.close());

const make = (o: { token?: string; socket?: string } = {}) => {
  const state = loadState(join(dir, "agent.state"), keyring);
  return createAgent({
    url: ids.url,
    version: "0.1.0",
    hostname: "nids-core-01",
    state,
    statePath: join(dir, "agent.state"),
    keyring,
    enrollToken: o.token ?? "oie_good",
    evePath: join(dir, "eve.json"),
    rulesDir: join(dir, "rules"),
    socketPath: o.socket,
  });
};
const alert = (sid: number) =>
  JSON.stringify({
    timestamp: "2026-10-28T13:58:12.114231+0000",
    event_type: "alert",
    src_ip: "192.0.2.17",
    dest_ip: "203.0.113.53",
    alert: { signature_id: sid },
  }) + "\n";

describe("the agent", () => {
  it("enrols once, keeps its secret sealed, writes the rules, reloads Suricata and sends eve.json", async () => {
    const socket = join(dir, "suricata.socket");
    const suricata = await fakeSuricata(socket);
    appendFileSync(join(dir, "eve.json"), alert(1) + alert(2));
    const agent = make({ socket });
    await agent.round();
    expect(ids.calls.map((c) => c.path)).toEqual(["/api/v1/agent/enroll", "/api/v1/agent/config", "/api/v1/agent/events"]);
    expect(readFileSync(join(dir, "agent.state"), "utf8")).not.toContain("oia_secret");
    expect(readFileSync(join(dir, "rules", "openasy.rules"), "utf8")).toContain(RULE);
    expect(readFileSync(join(dir, "rules", "threshold.config"), "utf8")).toContain("suppress gen_id 1, sig_id 2013028");
    expect(suricata.received).toEqual([{ version: "0.2" }, { command: "reload-rules" }]);
    expect(ids.calls[2]!.body.events).toHaveLength(2);

    // The next round reports what it wrote, does not reload again, and sends only what is new.
    appendFileSync(join(dir, "eve.json"), alert(3));
    await agent.round();
    const report = ids.calls.at(-2)!.body;
    expect(report.configHash).toBe(hashOf({ rules: [RULE], suppressions: ["suppress gen_id 1, sig_id 2013028"] }));
    expect(ids.calls.at(-1)!.body.events.map((e: any) => e.alert.signature_id)).toEqual([3]);
    expect(suricata.received).toHaveLength(2);
    await suricata.close();
  });

  it("refuses a rule that could reach outside Suricata, keeps the files it had and says why", async () => {
    const agent = make();
    await agent.round();
    const before = readFileSync(join(dir, "rules", "openasy.rules"), "utf8");
    ids.set({ rules: [RULE.replace("http.uri;", "lua:/tmp/evil.lua;")], suppressions: [] });
    await agent.round();
    expect(readFileSync(join(dir, "rules", "openasy.rules"), "utf8")).toBe(before);
    expect(agent.status.configError).toMatch(/lua/);
    // The refusal is reported, so the sensor shows it.
    await agent.round();
    expect(ids.calls.filter((c) => c.path === "/api/v1/agent/config").at(-1)!.body.configError).toMatch(/lua/);
  });

  it("says when Suricata could not reload, and tries again next round", async () => {
    const socket = join(dir, "suricata.socket");
    const suricata = await fakeSuricata(socket, { return: "NOK", message: "rule reload failed" });
    const agent = make({ socket });
    await agent.round();
    expect(agent.status.configError).toMatch(/could not reload/);
    await agent.round();
    expect(suricata.received.filter((m: any) => m.command === "reload-rules")).toHaveLength(2);
    await suricata.close();
  });

  it("keeps its place in eve.json while Network IDS is down", async () => {
    const agent = make();
    await agent.round();
    appendFileSync(join(dir, "eve.json"), alert(4));
    ids.down(true);
    await agent.round();
    expect(agent.status.idsOk).toBe(false);
    ids.down(false);
    await agent.round();
    expect(
      ids.calls
        .filter((c) => c.path === "/api/v1/agent/events")
        .at(-1)!
        .body.events.map((e: any) => e.alert.signature_id),
    ).toEqual([4]);
  });

  it("does nothing without a token, and says so", async () => {
    const agent = make({ token: "" });
    await agent.round();
    expect(ids.calls).toHaveLength(0);
    expect(agent.status.lastError).toMatch(/Not enrolled/);
    expect(existsSync(join(dir, "rules"))).toBe(false);
  });

  it("has health and metrics", async () => {
    const agent = make();
    await agent.round();
    const handler = createAgentHandler("0.1.0", agent.status);
    const server = createHttp(handler);
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    expect((await fetch(`${base}/readyz`)).status).toBe(200);
    expect(await (await fetch(`${base}/metrics`)).text()).toContain('openasy_build_info{product="network-ids-agent",version="0.1.0"} 1');
    await new Promise<void>((r) => server.close(() => r()));
  });

  it("reports a missing command socket", async () => {
    await expect(reloadRules(join(dir, "none.socket"), 1000)).rejects.toThrow(/command socket/);
  });
});
