import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { hashOf, render, ruleProblem, writeFiles } from "./rules.ts";

const ok = 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Admin; probe"; http.uri; content:"/admin"; sid:9000104; rev:1;)';

describe("rules from Network IDS", () => {
  it("are written when they are alert or pass rules with a local sid", () => {
    expect(ruleProblem(ok)).toBeNull();
    expect(ruleProblem(ok.replace("alert", "pass"))).toBeNull();
  });

  it("are refused when they could block, run scripts or touch files, whatever Network IDS checked", () => {
    expect(ruleProblem(ok.replace("alert", "drop"))).toMatch(/alert or pass/);
    expect(ruleProblem(ok.replace("http.uri;", "lua:/tmp/x.lua;"))).toMatch(/lua/);
    expect(ruleProblem(ok.replace("http.uri;", "dataset:set,x,type string,save /etc/passwd;"))).toMatch(/dataset/);
    expect(ruleProblem(ok.replace("http.uri;", "LuaJit:x;"))).toMatch(/luajit/);
    expect(ruleProblem(ok.replace("sid:9000104", "sid:2027758"))).toMatch(/sid/);
    expect(ruleProblem(`${ok}\nalert ip any any -> any any (sid:9000001;)`)).toMatch(/one line/);
    // Inside a quoted value, lua: is only text.
    expect(ruleProblem(ok.replace("LOCAL Admin; probe", "LOCAL lua:x; probe"))).toBeNull();
  });

  it("render two files, or none when one line is refused", () => {
    const files = render({ rules: [ok], suppressions: ["suppress gen_id 1, sig_id 2013028, track by_src, ip 192.0.2.0/24"] });
    expect(files.rules).toContain(`${ok}\n`);
    expect(files.threshold).toContain("suppress gen_id 1, sig_id 2013028, track by_src, ip 192.0.2.0/24\n");
    expect(() => render({ rules: [ok], suppressions: ["suppress gen_id 1, sig_id 1, track by_src, ip $(reboot)"] })).toThrow(/suppression/);
    expect(() => render({ rules: [ok, "include /etc/shadow"], suppressions: [] })).toThrow(/local rule/);
    expect(() => render({ rules: "x", suppressions: [] })).toThrow(/lists/);
  });

  it("are written whole and only when they change, with Network IDS's hash", () => {
    const dir = join(mkdtempSync(join(tmpdir(), "nids-agent-")), "rules");
    const files = render({ rules: [ok], suppressions: [] });
    expect(writeFiles(dir, files)).toBe(true);
    expect(writeFiles(dir, files)).toBe(false);
    expect(readFileSync(join(dir, "openasy.rules"), "utf8")).toBe(files.rules);
    // The same hash Network IDS gives: of the JSON of both lists.
    expect(hashOf({ rules: [], suppressions: [] })).toBe("cbffff3f072521e653adaddcadeb28fb023e28934c675c6c7de89df4d91fc3f9");
  });
});
