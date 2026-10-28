// The local rules and suppressions Network IDS gives this sensor (ADR 0070). They are data: every line is checked here
// again, whatever Network IDS checked, and only the agent's own two files are written. A compromised Network IDS can
// change what Suricata alerts on, not what runs on the sensor.
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const RULES_FILE = "openasy.rules";
export const THRESHOLD_FILE = "threshold.config";
const LOCAL_SID_MIN = 9_000_000;
const LOCAL_SID_MAX = 9_999_999;
/** Options that read or write files on the sensor or run scripts. */
const FORBIDDEN = new Set(["lua", "luajit", "dataset", "datarep"]);
const SUPPRESS = /^suppress gen_id \d{1,5}, sig_id \d{1,10}(, track by_(src|dst), ip [0-9A-Fa-f:.]{2,45}(\/\d{1,3})?)?$/;

/** The option names of a rule, outside quoted values. */
function optionNames(body: string): string[] {
  const names: string[] = [];
  let quoted = false;
  let start = true;
  let name = "";
  for (let i = 0; i < body.length; i++) {
    const ch = body[i]!;
    if (ch === "\\") {
      i++;
      continue;
    }
    if (ch === '"') quoted = !quoted;
    if (quoted) continue;
    if (start) {
      if (/[A-Za-z0-9_.-]/.test(ch)) name += ch;
      else if (ch === ":" || ch === ";") {
        if (name) names.push(name.toLowerCase());
        name = "";
        start = ch === ";";
      } else if (!/\s/.test(ch)) throw new Error(`unexpected ${ch}`);
    } else if (ch === ";") start = true;
  }
  if (quoted) throw new Error("a quote is not closed");
  if (name) names.push(name.toLowerCase());
  return names;
}

/** Why a rule line is not written, or null when it may be. */
export function ruleProblem(line: string): string | null {
  // eslint-disable-next-line no-control-regex
  if (line.length > 8192 || /[\u0000-\u001f\u007f]/.test(line)) return "not one line of at most 8192 characters";
  if (!/^(alert|pass) [a-z][a-z0-9-]{0,15} .+\(.*\)$/.test(line)) return "not an alert or pass rule";
  const body = line.slice(line.indexOf("(") + 1, -1);
  let names: string[];
  try {
    names = optionNames(body);
  } catch (err) {
    return `options do not read: ${(err as Error).message}`;
  }
  const bad = names.find((n) => FORBIDDEN.has(n));
  if (bad) return `the option ${bad} is not written`;
  const sid = /(?:^|;)\s*sid\s*:\s*(\d+)\s*;/.exec(body);
  if (!sid || Number(sid[1]) < LOCAL_SID_MIN || Number(sid[1]) > LOCAL_SID_MAX) return `the sid is not from ${LOCAL_SID_MIN} to ${LOCAL_SID_MAX}`;
  return null;
}

/** The two files, or the first line that is refused. */
export function render(c: { rules: unknown; suppressions: unknown }): { rules: string; threshold: string } {
  if (!Array.isArray(c.rules) || !Array.isArray(c.suppressions)) throw new Error("rules and suppressions must be lists");
  for (const r of c.rules) {
    const problem = typeof r === "string" ? ruleProblem(r) : "not a string";
    if (problem) throw new Error(`refused a local rule (${problem}): ${String(r).slice(0, 120)}`);
  }
  for (const s of c.suppressions) if (typeof s !== "string" || !SUPPRESS.test(s)) throw new Error(`refused a suppression: ${String(s).slice(0, 120)}`);
  const header = "# Written by network-ids-agent from OpenAsy Network IDS. Changes here are replaced: change them in Network IDS.\n";
  return {
    rules: header + c.rules.map((r) => `${r}\n`).join(""),
    threshold: header + c.suppressions.map((s) => `${s}\n`).join(""),
  };
}

export const hashOf = (c: { rules: string[]; suppressions: string[] }) =>
  createHash("sha256")
    .update(JSON.stringify({ rules: c.rules, suppressions: c.suppressions }))
    .digest("hex");

/** Writes a file whole or not at all, and only when it changes. Returns whether it changed. */
function writeAtomic(path: string, text: string): boolean {
  try {
    if (readFileSync(path, "utf8") === text) return false;
  } catch {
    // Not there yet.
  }
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, text, { mode: 0o644 });
  renameSync(tmp, path);
  return true;
}

export function writeFiles(dir: string, files: { rules: string; threshold: string }): boolean {
  mkdirSync(dir, { recursive: true });
  const a = writeAtomic(join(dir, RULES_FILE), files.rules);
  const b = writeAtomic(join(dir, THRESHOLD_FILE), files.threshold);
  return a || b;
}
