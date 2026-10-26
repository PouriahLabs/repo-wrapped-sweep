import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { SweepEnv } from "../src/env";
import type { CliIO } from "../src/cli";

// Fixture secrets are assembled at runtime from fragments so no committed
// literal is shaped like a credential (GitHub push protection, other scanners).

const ALPHA = "aB9cD2eF7gH4jK6mN1pQ8rS3tV5wX0yZ";
export function scramble(n: number, step = 7): string {
  let s = "";
  for (let i = 0; i < n; i++) s += ALPHA[(i * step + 3) % ALPHA.length];
  return s;
}

export const dashes = "-".repeat(5);
export const pemHeader = (kind: string) => `${dashes}BEGIN ${kind}${dashes}`;
export const pemFooter = (kind: string) => `${dashes}END ${kind}${dashes}`;

/** An unencrypted-looking RSA PEM block. `seed` varies the body. */
export function pemKey(seed = 0): string {
  return [
    pemHeader("RSA PRIVATE KEY"),
    scramble(64, 7 + seed * 2),
    scramble(64, 5 + seed * 2),
    scramble(40, 9),
    pemFooter("RSA PRIVATE KEY"),
    "",
  ].join("\n");
}

/** A GitHub-PAT-shaped token (body varies with `seed`). */
export function githubToken(seed = 0): string {
  return "gh" + "p_" + scramble(36, 7 + seed * 2);
}

export interface Fixture {
  root: string;
  home: string;
  env: SweepEnv;
  write(rel: string, content: string | Buffer): string;
  cleanup(): void;
}

/** A throwaway home directory + config dir, with a fake `SweepEnv` over it. */
export function makeFixture(overrides: Partial<SweepEnv> = {}): Fixture {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "sweep-test-"));
  const home = path.join(root, "home");
  fs.mkdirSync(home, { recursive: true });
  const env: SweepEnv = {
    platform: process.platform,
    home,
    cloudRoots: [],
    configDir: path.join(root, "cfg"),
    ...overrides,
  };
  return {
    root,
    home,
    env,
    write(rel, content) {
      const abs = path.join(home, rel);
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      fs.writeFileSync(abs, content);
      return abs;
    },
    cleanup() {
      fs.rmSync(root, { recursive: true, force: true });
    },
  };
}

/** An OpenSSH private-key container with the given cipher/KDF (built from bytes). */
export function openSshKey(opts: { encrypted: boolean } = { encrypted: false }): string {
  const str = (s: string) => {
    const b = Buffer.alloc(4 + s.length);
    b.writeUInt32BE(s.length, 0);
    b.write(s, 4, "latin1");
    return b;
  };
  const payload = Buffer.concat([
    Buffer.from("openssh-key-v1\0", "latin1"),
    str(opts.encrypted ? "aes256-ctr" : "none"),
    str(opts.encrypted ? "bcrypt" : "none"),
    str(""),
    Buffer.from(scramble(240), "latin1"),
  ]);
  const b64 = payload.toString("base64").replace(/(.{70})/g, "$1\n");
  return `${pemHeader("OPENSSH PRIVATE KEY")}\n${b64}\n${pemFooter("OPENSSH PRIVATE KEY")}\n`;
}

/** A CliIO that captures output. */
export function captureIO(): CliIO & { out: () => string; err: () => string } {
  let out = "";
  let err = "";
  return {
    stdout: { write: (s: string) => ((out += s), true), isTTY: false, columns: 120 },
    stderr: { write: (s: string) => ((err += s), true), isTTY: false },
    out: () => out,
    err: () => err,
  };
}
