# syntax=docker/dockerfile:1

# The agent has no runtime dependencies: Node runs the TypeScript sources directly, and it needs no other tool. It
# reads Suricata's eve.json, writes its two rule files and talks to Suricata's command socket (ADR 0070).
FROM node:26.13.0-trixie-slim AS build
RUN mkdir -p /out/data /out/rules

FROM gcr.io/distroless/nodejs26-debian13:nonroot
WORKDIR /app
COPY package.json ./
COPY agent ./agent
COPY --from=build --chown=nonroot:nonroot /out/data /data
COPY --from=build --chown=nonroot:nonroot /out/rules /rules
# The secret lives sealed in /data. Suricata's log directory is mounted read-only; /rules is the only directory the
# agent writes for Suricata.
ENV NODE_ENV=production PORT=9100 NETWORK_IDS_AGENT_STATE=/data/agent.state
VOLUME /data
EXPOSE 9100
USER nonroot
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:9100/healthz').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["agent/main.ts"]
