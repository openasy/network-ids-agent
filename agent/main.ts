import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { hostname } from "node:os";
import { createAgent } from "./agent.ts";
import { createAgentHandler } from "./app.ts";
import { createKeyring } from "./kek.ts";
import { log } from "./log.ts";
import { loadState } from "./state.ts";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
const url = process.env.NETWORK_IDS_URL;
if (!url) {
  log("error", "NETWORK_IDS_URL is required: the address of Network IDS, such as https://ids.example.com");
  process.exit(1);
}
if (!url.startsWith("https://") && !/^http:\/\/(localhost|127\.0\.0\.1|[a-z0-9-]+)(:\d+)?\/?$/.test(url))
  log("warn", "NETWORK_IDS_URL is not https: the agent's secret and the events cross the network in the clear", { url });
const keyFile = process.env.NETWORK_IDS_AGENT_SECRETS_KEY_FILE ?? "/run/secrets/openasy-agent-kek";
let kek: Buffer;
try {
  const text = readFileSync(keyFile, "utf8").trim();
  kek = /^[0-9a-f]{64}$/i.test(text) ? Buffer.from(text, "hex") : Buffer.from(text, "base64");
  if (kek.length !== 32) throw new Error("not 32 bytes");
} catch (err) {
  // The agent's secret lets anyone send events as this sensor: it does not start without the key that seals it (ADR 0021).
  log("error", "no key-encryption key: mount 32 random bytes (openssl rand -hex 32)", { file: keyFile, error: String(err) });
  process.exit(1);
}
const keyring = createKeyring(kek);
const statePath = process.env.NETWORK_IDS_AGENT_STATE ?? "/data/agent.state";
const state = loadState(statePath, keyring);
const pollSeconds = Number(process.env.POLL_SECONDS ?? 5);
const socketPath = process.env.SURICATA_SOCKET ?? "/var/run/suricata/suricata-command.socket";
const agent = createAgent({
  url,
  version,
  hostname: process.env.SENSOR_HOSTNAME || hostname(),
  state,
  statePath,
  keyring,
  enrollToken: process.env.NETWORK_IDS_ENROLL_TOKEN || undefined,
  evePath: process.env.EVE_FILE ?? "/var/log/suricata/eve.json",
  rulesDir: process.env.RULES_DIR ?? "/rules",
  socketPath: socketPath || undefined,
});

const port = Number(process.env.PORT ?? 9100);
const server = createServer(createAgentHandler(version, agent.status));
server.listen(port, () => log("info", "network-ids-agent started", { version, port, networkIds: url, enrolled: agent.status.enrolled, sensor: state.name }));

let busy = false;
const tick = () => {
  if (busy) return;
  busy = true;
  agent
    .round()
    .catch((err: unknown) => log("error", "round failed", { error: String(err) }))
    .finally(() => (busy = false));
};
tick();
const timer = setInterval(tick, pollSeconds * 1000);

function shutdown(signal: string) {
  log("info", "shutting down", { signal });
  clearInterval(timer);
  setTimeout(() => process.exit(1), 10_000).unref();
  server.close(() => process.exit(0));
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
