// Asks Suricata to reload its rules over its command socket (unix-command in suricata.yaml), as suricatasc does. The
// agent sends this one command, of its own accord, after writing its files; nothing it receives decides what is sent.
import { connect } from "node:net";

/** Sends one JSON message and reads one JSON answer. */
function exchange(sock: ReturnType<typeof connect>, message: unknown, timeoutMs: number, newline = true): Promise<{ return?: string; message?: unknown }> {
  return new Promise((resolve, reject) => {
    let text = "";
    const timer = setTimeout(() => (cleanup(), reject(new Error("Suricata did not answer in time"))), timeoutMs);
    const onData = (d: Buffer) => {
      text += d.toString("utf8");
      try {
        const answer = JSON.parse(text) as { return?: string; message?: unknown };
        cleanup();
        resolve(answer);
      } catch {
        // Not whole yet.
      }
    };
    const onError = (err: Error) => (cleanup(), reject(err));
    const cleanup = () => {
      clearTimeout(timer);
      sock.off("data", onData);
      sock.off("error", onError);
    };
    sock.on("data", onData);
    sock.on("error", onError);
    sock.write(JSON.stringify(message) + (newline ? "\n" : ""));
  });
}

export async function reloadRules(socketPath: string, timeoutMs = 120_000): Promise<void> {
  const sock = connect(socketPath);
  try {
    await new Promise<void>((resolve, reject) => {
      // A socket file left by a Suricata that is gone, or on a filesystem that does not pass sockets, may never answer.
      const timer = setTimeout(() => reject(new Error(`Suricata's command socket ${socketPath} does not answer`)), 10_000);
      sock.once("connect", () => (clearTimeout(timer), resolve()));
      sock.once("error", (err) => (clearTimeout(timer), reject(new Error(`Suricata's command socket ${socketPath}: ${err.message}`))));
    });
    // As suricatasc: the version message alone, then protocol 0.2 takes each command ended by a newline.
    const hello = await exchange(sock, { version: "0.2" }, 10_000, false);
    if (hello.return !== "OK") throw new Error(`Suricata refused the command protocol: ${JSON.stringify(hello.message)}`);
    const r = await exchange(sock, { command: "reload-rules" }, timeoutMs);
    if (r.return !== "OK") throw new Error(`Suricata could not reload its rules: ${JSON.stringify(r.message)}`);
  } finally {
    sock.destroy();
  }
}
