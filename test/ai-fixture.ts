// Transcript fixtures for the AI-usage collector: Claude Code and Codex lines in the shapes the
// shared parser reads, with a SENTINEL planted in every text-bearing slot (prompt, reply,
// tool input, instructions) so tests can grep every output for it.

import fs from "node:fs";
import path from "node:path";

export const SENTINEL = "SENTINEL_d41d8cd9_MESSAGE_TEXT";

export interface CcTurn {
  id: string;
  at: number;
  session: string;
  cwd: string;
  model?: string;
  input?: number;
  output?: number;
  cacheWrite?: number;
  cacheRead?: number;
}

/** One Claude Code assistant line (one content block of a response). */
export function ccLine(t: CcTurn): string {
  return JSON.stringify({
    parentUuid: null,
    isSidechain: false,
    type: "assistant",
    message: {
      model: t.model ?? "claude-opus-5-5",
      id: `msg_${t.id}`,
      type: "message",
      role: "assistant",
      content: [
        { type: "text", text: `${SENTINEL} reply` },
        {
          type: "tool_use",
          id: "toolu_1",
          name: "Edit",
          input: { new_string: `${SENTINEL} code` },
        },
      ],
      usage: {
        input_tokens: t.input ?? 10,
        output_tokens: t.output ?? 100,
        cache_creation_input_tokens: t.cacheWrite ?? 0,
        cache_read_input_tokens: t.cacheRead ?? 0,
      },
    },
    requestId: `req_${t.id}`,
    uuid: `u-${t.id}`,
    timestamp: new Date(t.at).toISOString(),
    sessionId: t.session,
    cwd: t.cwd,
  });
}

/** A Claude Code user line carrying only text. */
export function ccUserLine(at: number, session: string, cwd: string): string {
  return JSON.stringify({
    type: "user",
    message: { role: "user", content: `${SENTINEL} prompt` },
    timestamp: new Date(at).toISOString(),
    sessionId: session,
    cwd,
  });
}

export function codexMeta(at: number, session: string, cwd: string, model = "gpt-5.5"): string[] {
  return [
    JSON.stringify({
      timestamp: new Date(at).toISOString(),
      type: "session_meta",
      payload: { id: session, cwd, base_instructions: { text: `${SENTINEL} instructions` } },
    }),
    JSON.stringify({
      timestamp: new Date(at).toISOString(),
      type: "turn_context",
      payload: { cwd, model, summary: `${SENTINEL} summary` },
    }),
  ];
}

export function codexText(at: number): string {
  return JSON.stringify({
    timestamp: new Date(at).toISOString(),
    type: "response_item",
    payload: {
      type: "message",
      role: "user",
      content: [{ type: "input_text", text: `${SENTINEL} usage` }],
    },
  });
}

/** A token_count event; `total` is the session's running total (repeats are dropped). */
export function codexTokens(
  at: number,
  total: number,
  input: number,
  cached: number,
  output: number,
): string {
  return JSON.stringify({
    timestamp: new Date(at).toISOString(),
    type: "event_msg",
    payload: {
      type: "token_count",
      info: {
        total_token_usage: { total_tokens: total },
        last_token_usage: {
          input_tokens: input,
          cached_input_tokens: cached,
          output_tokens: output,
        },
      },
    },
  });
}

export function writeLines(abs: string, lines: string[]): string {
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, lines.map((l) => `${l}\n`).join(""));
  return abs;
}

export function appendLines(abs: string, lines: string[], trailing = ""): void {
  fs.appendFileSync(abs, lines.map((l) => `${l}\n`).join("") + trailing);
}
