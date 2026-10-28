import type { IncomingMessage, ServerResponse } from "node:http";
import type { Status } from "./agent.ts";

function send(res: ServerResponse, status: number, body: string, type = "application/json") {
  res.writeHead(status, { "content-type": type, "content-length": Buffer.byteLength(body), "x-content-type-options": "nosniff" });
  res.end(body);
}

/** Health and metrics for the agent (ADR 0017). The agent has no API of its own. */
export function createAgentHandler(version: string, s: Status) {
  return (req: IncomingMessage, res: ServerResponse) => {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    if (path === "/healthz") return send(res, 200, JSON.stringify({ status: "ok" }));
    if (path === "/readyz") {
      const problems = [
        !s.enrolled && "not enrolled",
        !s.idsOk && `network-ids unreachable${s.lastError ? `: ${s.lastError}` : ""}`,
        s.configError && `rules not applied: ${s.configError}`,
      ].filter(Boolean);
      return send(res, problems.length ? 503 : 200, JSON.stringify(problems.length ? { status: "degraded", problems } : { status: "ready" }));
    }
    if (path === "/metrics") {
      const lines = [
        "# HELP openasy_build_info Build information.",
        "# TYPE openasy_build_info gauge",
        `openasy_build_info{product="network-ids-agent",version="${version}"} 1`,
        "# HELP openasy_network_ids_agent_events_sent_total EVE events sent to Network IDS.",
        "# TYPE openasy_network_ids_agent_events_sent_total counter",
        `openasy_network_ids_agent_events_sent_total ${s.eventsSent}`,
        "# HELP openasy_network_ids_agent_lines_skipped_total Lines of eve.json not sent: other event types, not JSON, too long.",
        "# TYPE openasy_network_ids_agent_lines_skipped_total counter",
        `openasy_network_ids_agent_lines_skipped_total ${s.linesSkipped}`,
        "# HELP openasy_network_ids_agent_reloads_total Times Suricata was asked to reload its rules.",
        "# TYPE openasy_network_ids_agent_reloads_total counter",
        `openasy_network_ids_agent_reloads_total ${s.reloads}`,
        "# HELP openasy_network_ids_agent_config_ok Whether the last rules were written and loaded.",
        "# TYPE openasy_network_ids_agent_config_ok gauge",
        `openasy_network_ids_agent_config_ok ${s.configError ? 0 : 1}`,
        "# HELP openasy_network_ids_agent_last_contact_timestamp_seconds Last successful call to Network IDS; 0 before the first.",
        "# TYPE openasy_network_ids_agent_last_contact_timestamp_seconds gauge",
        `openasy_network_ids_agent_last_contact_timestamp_seconds ${s.lastContactAt ? Math.floor(Date.parse(s.lastContactAt) / 1000) : 0}`,
      ];
      return send(res, 200, lines.join("\n") + "\n", "text/plain; version=0.0.4");
    }
    send(res, 404, JSON.stringify({ status: "not found" }));
  };
}
