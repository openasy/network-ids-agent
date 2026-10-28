# network-ids-agent

[![CI](https://github.com/openasy/network-ids-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/network-ids-agent/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The agent of [OpenAsy Network IDS](https://github.com/openasy/network-ids). It runs **next to Suricata on each
sensor**, sends what Suricata writes to Network IDS, and writes the local rules and suppressions kept there for
Suricata to load (ADR 0070, 0023).

- **It sends what Suricata saw.** It reads `eve.json` from where it stopped, follows it across rotation, and sends the
  `alert`, `flow`, `dns`, `http`, `tls`, `ssh` and `stats` events in gzipped batches. Packet payloads, HTTP bodies and
  the rule text Suricata can add to an alert stay on the sensor. Its place in the file moves only once a batch is
  taken, so nothing is lost while Network IDS is down, and a batch sent twice counts once there.
- **It writes rules as data, never runs commands.** It asks for the enabled local rules and active suppressions,
  checks every line again (an `alert` or `pass` rule with a sid from 9,000,000 to 9,999,999 and no `lua`, `luajit`,
  `dataset` or `datarep`; Suricata's `suppress` form), and writes them whole to `openasy.rules` and
  `threshold.config` in its rules directory, and nowhere else. One refused line keeps the files it had, and the
  sensor shows why. Then it asks Suricata to reload its rules over the command socket, the one command it sends, of
  its own accord. A compromised Network IDS can change what alerts, not what runs on the sensor.
- **It connects out, never in.** It enrols once with a one-time token and then calls with its own secret, kept in
  `/data/agent.state` sealed with its own key-encryption key (ADR 0021). It has no API; `/healthz`, `/readyz` and
  `/metrics` are on port 9100.

## Run

Add the sensor in Network IDS under Sensors. It shows a one-time enrolment token and this command, for the sensor host:

```bash
openssl rand -hex 32 > openasy-agent-kek   # keep it with your backups
docker run -d --name network-ids-agent --restart unless-stopped --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  -v network-ids-agent-data:/data -v "$PWD/openasy-agent-kek:/run/secrets/openasy-agent-kek:ro" \
  -v /var/log/suricata:/var/log/suricata:ro -v /etc/suricata/openasy:/rules \
  -v /var/run/suricata:/var/run/suricata \
  -e NETWORK_IDS_URL=https://ids.example.com -e NETWORK_IDS_ENROLL_TOKEN=oie_... \
  ghcr.io/openasy/network-ids-agent:0.1.0
```

The agent runs as uid 65532. It must be able to read `eve.json`, write `/etc/suricata/openasy` and write to Suricata's
command socket: give it Suricata's group with `--group-add` (or run it as Suricata's user with `--user`). It must be
the same version as Network IDS (ADR 0019); another version is refused.

In `suricata.yaml`, write EVE JSON with the event types above (`community-id: true` links flows to other tools), add
`/etc/suricata/openasy/openasy.rules` to `rule-files`, set `threshold-file: /etc/suricata/openasy/threshold.config`,
and enable `unix-command`. The threshold file is the agent's: suppressions you kept in another one move to Network
IDS. Rulesets such as ET Open stay with `suricata-update`.

| Variable | Default | |
| --- | --- | --- |
| `NETWORK_IDS_URL` | | Where Network IDS is, its https:// address |
| `NETWORK_IDS_ENROLL_TOKEN` | | One-time, for the first start only |
| `NETWORK_IDS_AGENT_SECRETS_KEY_FILE` | `/run/secrets/openasy-agent-kek` | 32-byte key that seals the agent's secret |
| `NETWORK_IDS_AGENT_STATE` | `/data/agent.state` | The sealed state, on its volume |
| `EVE_FILE` | `/var/log/suricata/eve.json` | Suricata's EVE JSON log |
| `RULES_DIR` | `/rules` | Where `openasy.rules` and `threshold.config` are written |
| `SURICATA_SOCKET` | `/var/run/suricata/suricata-command.socket` | Suricata's command socket; empty to reload Suricata yourself |
| `SENSOR_HOSTNAME` | the container's | The name shown for the host |
| `POLL_SECONDS` | `5` | How often it asks for rules and sends events |
| `PORT` | `9100` | `/healthz`, `/readyz` and `/metrics` |

## Not yet

Zeek's logs, packet captures on demand, and lines of a rotated file that were not read before it rotated (the agent
starts the new file at its beginning) are planned.

## Develop

```bash
npm install
npm test   # reading eve.json across rotation, checking rules, writing files, the command socket, the loop
```

## Licence

AGPL-3.0 (ADR 0008).
