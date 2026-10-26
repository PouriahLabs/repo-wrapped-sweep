// Machine Wrapped (ENDPOINT-MACHINE-INSIGHTS § C2.6, C-7): the year on this machine as a
// self-contained HTML card, optionally screenshotted to PNG by a Chrome/Edge already
// installed. Local only — no upload, no network. The numbers come from the collectors that
// already exist (the discovery walk + git for commits, the AI-usage store for sessions) and
// are folded by the shared pure core `@/lib/endpoint/insights/machine-wrapped`.
//
// The card carries aggregates only: no repo names, no paths, no email, no message text — it
// is made to be shared.

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  languageOfPath,
  type LocalParts,
  type MachineWrapped,
  type WrappedCommit,
} from "@/lib/endpoint/insights/machine-wrapped";
import type { DeviceConfig } from "./device";
import type { SweepEnv } from "./env";
import { formatMinutes, formatTokens, formatUsd, COST_LABEL } from "./insights/ai-report";
import { formatBytes } from "./insights/disk";
import { git, GIT_COMMAND_TIMEOUT_MS, GIT_POOL } from "./insights/git";
import { findOnPath, mapPool } from "./insights/run";
import type { Exec } from "./platform";
import { escapeHtml } from "./report";

/**
 * Why `wrapped --share` may not run here, or null when it may. Publishing to a public page is
 * something a person chooses each time at a terminal, as the account that owns the device:
 *   - never from a scheduled / MDM-driven run (`--scheduled`);
 *   - never where the administrator turned insights off (MDM `insights: false`);
 *   - only from an enrolled device, and only a PERSONAL one — a device that reports to an
 *     organization must not publish to a person's profile (the server refuses it as well).
 */
export function shareRefusal(opts: {
  scheduled: boolean;
  mdmInsights: boolean | undefined;
  device: DeviceConfig | null;
}): string | null {
  if (opts.scheduled) {
    return "--share cannot be used in a scheduled run: publishing is something you choose each time, at a terminal.";
  }
  if (opts.mdmInsights === false) {
    return "--share is turned off on this machine: your administrator disabled machine insights (insights: false).";
  }
  if (!opts.device) {
    return "--share needs an enrolled device (sharing is part of Pro). Add a device in Workspace → Endpoints, then run `repo-wrapped-sweep enrol <token>`.";
  }
  if (opts.device.orgLogin) {
    return `--share is for personal devices. This one reports to the organization ${opts.device.orgLogin}; a company machine does not publish to a personal profile.`;
  }
  return null;
}

/** `git log` over a year can be long on a big repo. */
export const WRAPPED_LOG_TIMEOUT_MS = 20_000;
const LOG_MAX_BYTES = 16 * 1024 * 1024;
const DAY_MS = 86_400_000;

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

/** Local calendar year bounds, epoch ms, [start, end). */
export function yearBounds(year: number): { start: number; end: number } {
  return { start: new Date(year, 0, 1).getTime(), end: new Date(year + 1, 0, 1).getTime() };
}

/** This machine's local calendar parts (the card speaks in local days and hours). */
export function localParts(at: number): LocalParts {
  const d = new Date(at);
  const day = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  return { day, weekday: d.getDay(), hour: d.getHours() };
}

export interface YearCommits {
  commits: WrappedCommit[];
  languageFiles: Record<string, number>;
  /** Repos with no `user.email` configured (their commits can't be attributed). */
  noEmail: number;
  /** Repos git didn't answer for in time. */
  unknown: number;
}

/**
 * Your commits in [start, end) across `repos`: `git log --all --no-merges` filtered by each
 * repo's own `user.email`, with the files each commit changed (for the language mix). A commit
 * seen in two clones is counted once (by hash). Read-only, no network.
 */
export async function collectYearCommits(
  repos: readonly string[],
  opts: { env: SweepEnv; start: number; end: number },
): Promise<YearCommits> {
  const out: YearCommits = { commits: [], languageFiles: {}, noEmail: 0, unknown: 0 };
  const seen = new Set<string>();
  const results = await mapPool(repos, GIT_POOL, async (repo) => {
    const email = await git(opts.env, repo, ["config", "user.email"], GIT_COMMAND_TIMEOUT_MS);
    if (!email.ok) return { repo, failed: true as const };
    const who = email.code === 0 ? email.stdout.trim() : "";
    if (!who) return { repo, noEmail: true as const };
    const log = await git(
      opts.env,
      repo,
      [
        "log",
        "--all",
        "--no-merges",
        "--fixed-strings",
        `--author=${who}`,
        `--since=${new Date(opts.start - DAY_MS).toISOString()}`,
        `--until=${new Date(opts.end + DAY_MS).toISOString()}`,
        "--format=@%H %ct",
        "--name-only",
      ],
      WRAPPED_LOG_TIMEOUT_MS,
      LOG_MAX_BYTES,
    );
    if (!log.ok || log.code !== 0) return { repo, failed: true as const };
    return { repo, stdout: log.stdout };
  });

  for (const r of results) {
    if ("failed" in r) {
      out.unknown++;
      continue;
    }
    if ("noEmail" in r) {
      out.noEmail++;
      continue;
    }
    let counting = false;
    for (const raw of r.stdout.split("\n")) {
      const line = raw.replace(/\r$/, "");
      if (line.startsWith("@")) {
        const [hash, secs] = line.slice(1).split(" ");
        const at = Number(secs) * 1000;
        counting = false;
        if (!hash || !Number.isFinite(at) || at < opts.start || at >= opts.end || seen.has(hash)) {
          continue;
        }
        seen.add(hash);
        out.commits.push({ at, hash, repo: r.repo });
        counting = true;
      } else if (counting && line) {
        const lang = languageOfPath(line);
        if (lang) out.languageFiles[lang] = (out.languageFiles[lang] ?? 0) + 1;
      }
    }
  }
  return out;
}

/**
 * Bytes freed by `disk clean` in [start, end), from its log (`clean-log.jsonl`: one
 * `{ path, bytes, time }` per deletion). Null when there is no log — the card then says nothing.
 */
export function readDiskReclaimed(env: SweepEnv, start: number, end: number): number | null {
  let raw: string;
  try {
    raw = fs.readFileSync(path.join(env.configDir, "clean-log.jsonl"), "utf8");
  } catch {
    return null;
  }
  let total = 0;
  for (const line of raw.split("\n")) {
    try {
      const j = JSON.parse(line) as { bytes?: unknown; time?: unknown };
      const t = typeof j.time === "string" ? Date.parse(j.time) : Number.NaN;
      if (typeof j.bytes === "number" && j.bytes > 0 && t >= start && t < end) total += j.bytes;
    } catch {
      // blank or partial line
    }
  }
  return total;
}

// ---------------------------------------------------------------------------
// PNG via a browser already on the machine
// ---------------------------------------------------------------------------

/** Chrome / Edge / Chromium, or null. Never downloads anything. */
export function findBrowser(env: SweepEnv): string | null {
  const pe = env.processEnv ?? process.env;
  const exists = env.fileExists ?? ((p: string) => fs.existsSync(p));
  const candidates: string[] = [];
  if (env.platform === "win32") {
    for (const base of [pe.ProgramFiles, pe["ProgramFiles(x86)"], pe.LOCALAPPDATA]) {
      if (!base) continue;
      candidates.push(
        path.join(base, "Google", "Chrome", "Application", "chrome.exe"),
        path.join(base, "Microsoft", "Edge", "Application", "msedge.exe"),
      );
    }
  } else if (env.platform === "darwin") {
    candidates.push(
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
      "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
      "/Applications/Chromium.app/Contents/MacOS/Chromium",
    );
  } else {
    for (const name of [
      "google-chrome",
      "google-chrome-stable",
      "chromium",
      "chromium-browser",
      "microsoft-edge",
    ]) {
      const hit = findOnPath(name, { path: pe.PATH ?? "", platform: env.platform });
      if (hit) return hit;
    }
  }
  return candidates.find((c) => exists(c)) ?? null;
}

export const CARD_WIDTH = 1080;
export const CARD_HEIGHT = 1350;

/** Screenshot the card with headless Chrome/Edge. Resolves to an error message, or null on success. */
export async function renderPng(
  browser: string,
  htmlFile: string,
  pngFile: string,
  exec: Exec,
): Promise<string | null> {
  try {
    fs.rmSync(pngFile, { force: true });
  } catch {
    // not there
  }
  const r = await exec(
    browser,
    [
      "--headless=new",
      "--disable-gpu",
      "--hide-scrollbars",
      "--no-first-run",
      "--force-dark-mode",
      "--force-device-scale-factor=1",
      `--window-size=${CARD_WIDTH},${CARD_HEIGHT}`,
      `--screenshot=${pngFile}`,
      pathToFileURL(htmlFile).href,
    ],
    { timeoutMs: 60_000 },
  );
  if (fs.existsSync(pngFile)) return null;
  return `the browser exited with code ${r.code}`;
}

// ---------------------------------------------------------------------------
// The card
// ---------------------------------------------------------------------------

/**
 * The site's data-viz tokens (src/styles/tokens.css), dark then light. Copied because the card
 * is self-contained; a root test keeps these values identical to tokens.css.
 */
export const CARD_TOKENS_DARK =
  "--chart-1:247 69% 72%;--chart-2:159 73% 36%;--chart-3:40 100% 39%;--chart-4:213 77% 56%;--chart-5:0 72% 65%;--chart-other:42 7% 62%;--heat-0:40 4% 18%;--heat-1:250 39% 48%;--heat-2:250 52% 59%;--heat-3:251 66% 69%;--heat-4:248 81% 79%;";
export const CARD_TOKENS_LIGHT =
  "--chart-1:249 48% 44%;--chart-2:159 73% 40%;--chart-3:41 100% 46%;--chart-4:213 68% 50%;--chart-5:0 73% 59%;--chart-other:35 7% 40%;--heat-0:40 18% 93%;--heat-1:252 63% 76%;--heat-2:252 59% 66%;--heat-3:251 50% 55%;--heat-4:249 48% 44%;";

const CARD_CSS = `:root{color-scheme:dark light;--bg:40 6% 10%;--fg:40 14% 90%;--card:40 5% 13%;--border:40 4% 22%;--muted:42 7% 62%;${CARD_TOKENS_DARK}}
@media (prefers-color-scheme:light){:root{--bg:40 30% 97%;--fg:30 8% 14%;--card:40 40% 99%;--border:40 14% 86%;--muted:35 7% 40%;${CARD_TOKENS_LIGHT}}}
*{box-sizing:border-box}body{margin:0;background:hsl(var(--bg));color:hsl(var(--fg));font:16px/1.4 system-ui,-apple-system,"Segoe UI",sans-serif}
.card{width:${CARD_WIDTH}px;min-height:${CARD_HEIGHT}px;margin:0 auto;padding:56px 64px;display:flex;flex-direction:column;gap:28px}
.eyebrow{font-size:14px;letter-spacing:.14em;text-transform:uppercase;color:hsl(var(--muted))}
h1{font-size:64px;line-height:1;margin:6px 0 0;font-weight:800;letter-spacing:-.02em}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.stat{background:hsl(var(--card));border:1px solid hsl(var(--border));border-radius:16px;padding:18px 20px}
.stat b{display:block;font-size:44px;line-height:1.05;font-weight:750;font-variant-numeric:tabular-nums}
.stat span{color:hsl(var(--muted));font-size:14px}
.panel{background:hsl(var(--card));border:1px solid hsl(var(--border));border-radius:16px;padding:18px 20px}
.panel h2{font-size:13px;letter-spacing:.1em;text-transform:uppercase;color:hsl(var(--muted));margin:0 0 12px;font-weight:600}
.row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.bar{display:flex;height:18px;border-radius:9px;overflow:hidden;background:hsl(var(--heat-0))}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;margin-top:10px;font-size:14px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;vertical-align:baseline}
.cols{display:grid;grid-template-columns:repeat(7,1fr);gap:8px;align-items:end;height:120px}
.cols div{display:flex;flex-direction:column;justify-content:flex-end;height:100%;text-align:center;font-size:12px;color:hsl(var(--muted))}
.cols div i{display:block;background:hsl(var(--chart-1));border-radius:4px 4px 0 0;min-height:2px;margin-bottom:6px}
.cols div.top{color:hsl(var(--fg));font-weight:700}
.hours{display:grid;grid-template-columns:repeat(24,1fr);gap:3px}.hours i{height:28px;border-radius:3px}
.hourlabels{display:grid;grid-template-columns:repeat(4,1fr);font-size:12px;color:hsl(var(--muted));margin-top:6px}
.big{font-size:34px;font-weight:750;line-height:1.1}
.muted{color:hsl(var(--muted))}.small{font-size:13px}
footer{margin-top:auto;font-size:13px;color:hsl(var(--muted))}`;

const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const WEEKDAY_NAMES = [
  "Sunday",
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
];

export function hourLabel(h: number): string {
  if (h === 0) return "midnight";
  if (h === 12) return "noon";
  return h < 12 ? `${h} am` : `${h - 12} pm`;
}

const n = (x: number) => x.toLocaleString("en-US");

/** Heat level 0–4 for a value relative to the max (0 only for no activity). */
function heat(v: number, max: number): number {
  if (v <= 0 || max <= 0) return 0;
  return Math.min(4, Math.max(1, Math.ceil((v / max) * 4)));
}

export function renderWrappedHtml(w: MachineWrapped, ctx: { version: string }): string {
  const e = escapeHtml;
  const ai = w.ai;
  const stat = (value: string, label: string) =>
    `<div class="stat"><b>${e(value)}</b><span>${e(label)}</span></div>`;

  const langs =
    w.languages.length === 0
      ? `<p class="muted">No commits by you on this machine in ${w.year}.</p>`
      : (() => {
          const shown = w.languages.reduce((s, l) => s + l.pct, 0);
          const other = Math.max(0, Math.round((100 - shown) * 10) / 10);
          const parts = [
            ...w.languages.map((l) => ({
              name: l.name,
              pct: l.pct,
              color: l.color ?? "hsl(var(--chart-other))",
            })),
            ...(other >= 1
              ? [{ name: "Other", pct: other, color: "hsl(var(--chart-other))" }]
              : []),
          ];
          return `<div class="bar">${parts
            .map(
              (p) =>
                `<span style="width:${p.pct}%;background:${e(p.color)}" title="${e(p.name)}"></span>`,
            )
            .join("")}</div>
<div class="legend">${parts
            .map(
              (p) => `<span><i style="background:${e(p.color)}"></i>${e(p.name)} ${p.pct}%</span>`,
            )
            .join("")}</div>`;
        })();

  const share = w.aiShare === null ? null : Math.round(w.aiShare * 100);
  const shareBar =
    share === null
      ? `<p class="muted">No activity recorded.</p>`
      : `<div class="big">${share}%</div>
<p class="muted small">of active time was AI-assisted (AI-active ÷ AI-active + commit-active minutes)</p>
<div class="bar"><span style="width:${share}%;background:hsl(var(--chart-1))"></span><span style="width:${100 - share}%;background:hsl(var(--chart-2))"></span></div>
<div class="legend"><span><i style="background:hsl(var(--chart-1))"></i>AI sessions ${e(formatMinutes(ai.activeMinutes))}</span><span><i style="background:hsl(var(--chart-2))"></i>Commits ${e(formatMinutes(w.commitActiveMinutes))}</span></div>`;

  const maxDay = Math.max(0, ...w.weekdayActivity);
  const weekdays = w.weekdayActivity
    .map(
      (v, i) =>
        `<div class="${i === w.busiestWeekday ? "top" : ""}"><i style="height:${maxDay > 0 ? Math.round((v / maxDay) * 100) : 0}%"></i>${WEEKDAYS[i]}</div>`,
    )
    .join("");
  const maxHour = Math.max(0, ...w.hourActivity);
  const hours = w.hourActivity
    .map(
      (v, h) =>
        `<i style="background:hsl(var(--heat-${heat(v, maxHour)}))" title="${e(hourLabel(h))}"></i>`,
    )
    .join("");

  const cost = ai.costUsd === null ? "—" : formatUsd(ai.costUsd);

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=${CARD_WIDTH}">
<title>Machine Wrapped ${w.year}</title>
<style>
${CARD_CSS}
</style>
</head>
<body>
<main class="card">
<header>
<div class="eyebrow">Machine Wrapped</div>
<h1>${w.year} on this machine</h1>
</header>
<section class="grid">
${stat(n(w.commits), "commits")}
${stat(n(w.reposTouched), w.reposTouched === 1 ? "repo touched" : "repos touched")}
${stat(`${n(w.longestStreakDays)}d`, "longest streak")}
${stat(n(ai.sessions), "AI sessions")}
${stat(`${n(Math.round(ai.activeMinutes / 60))}h`, "AI-active hours")}
${stat(n(w.activeDays), "active days")}
</section>
<section class="panel"><h2>Languages</h2>
${langs}
</section>
<section class="row">
<div class="panel"><h2>AI share</h2>
${shareBar}
</div>
<div class="panel"><h2>AI</h2>
<div class="big">${e(ai.topModel ?? "—")}</div>
<p class="muted small">top model by responses</p>
<p><b>${e(formatTokens(ai.tokens))}</b> tokens · <b>${e(cost)}</b> ${e(COST_LABEL)}</p>
<p class="muted small">Not a bill: what the same tokens would cost on the pay-as-you-go API. Prices as of ${e(ai.pricesAsOf)}.${ai.unpriced.length ? ` Unpriced: ${e(ai.unpriced.join(", "))}.` : ""}</p>
</div>
</section>
<section class="row">
<div class="panel"><h2>Busiest day${w.busiestWeekday === null ? "" : ` · ${e(WEEKDAY_NAMES[w.busiestWeekday]!)}`}</h2>
<div class="cols">${weekdays}</div>
</div>
<div class="panel"><h2>Busiest hour${w.busiestHour === null ? "" : ` · ${e(hourLabel(w.busiestHour))}`}</h2>
<div class="hours">${hours}</div>
<div class="hourlabels"><span>midnight</span><span>6 am</span><span>noon</span><span>6 pm</span></div>
<p class="muted small">active hours, local time</p>
</div>
</section>
${
  w.diskReclaimedBytes !== null
    ? `<section class="panel"><h2>Disk reclaimed</h2><div class="big">${e(formatBytes(w.diskReclaimedBytes))}</div><p class="muted small">freed by disk clean this year</p></section>`
    : ""
}
<footer>${e(COST_LABEL)} · prices as of ${e(ai.pricesAsOf)} · made locally by repo-wrapped-sweep ${e(ctx.version)} — this file stays on your machine</footer>
</main>
</body>
</html>
`;
}

/** The terminal summary printed after writing the card. */
export function renderWrappedText(w: MachineWrapped): string {
  const plural = (k: number, one: string) => `${n(k)} ${one}${k === 1 ? "" : "s"}`;
  const lines = [
    `Machine Wrapped ${w.year}`,
    `  ${plural(w.commits, "commit")} across ${plural(w.reposTouched, "repo")} · ${plural(w.activeDays, "active day")} · longest streak ${n(w.longestStreakDays)}d`,
    `  ${plural(w.ai.sessions, "AI session")} · ${formatMinutes(w.ai.activeMinutes)} AI-active · top model ${w.ai.topModel ?? "—"} · ${formatUsd(w.ai.costUsd)} ${COST_LABEL} (prices as of ${w.ai.pricesAsOf})`,
  ];
  if (w.languages.length > 0) {
    lines.push(`  languages: ${w.languages.map((l) => `${l.name} ${l.pct}%`).join(", ")}`);
  }
  if (w.aiShare !== null) lines.push(`  AI share of active time: ${Math.round(w.aiShare * 100)}%`);
  if (w.busiestWeekday !== null && w.busiestHour !== null) {
    lines.push(
      `  busiest: ${WEEKDAY_NAMES[w.busiestWeekday]}s, around ${hourLabel(w.busiestHour)}`,
    );
  }
  return lines.join("\n");
}
