// Shell parsing for the agent guard (§ A2.7, A7): a quote-aware tokenizer for
// bash, PowerShell and cmd, and detection of the commands that read a whole
// DIRECTORY TREE (`grep -r`, `rg`, `findstr /s`, `Select-String -Recurse`, a
// recursive `Get-ChildItem` piped to a reader).
//
// Pure — no file system. The directory walk lives in `hook-search.ts`. This is
// best-effort pattern matching over argument vectors, not a shell: reads hidden
// inside an interpreter (`node -e`, `python -c`, a script) are not visible here.

export interface Segment {
  words: string[];
  /** The segment's stdin is the previous segment's stdout (`a | b`). */
  piped: boolean;
}

const SEGMENT_BREAK = new Set([";", "|", "&", "(", ")", "`", "\n", "\r"]);
const REDIRECT = new Set(["<", ">"]);

/**
 * Split a command into simple commands, each a list of word tokens. Honours
 * single/double quotes; `; | & ( ) \`` and newlines end a command; `< >` only end
 * a word (so a redirect target surfaces as its own token). Backslashes are
 * literal — a Windows path must survive — so this errs toward over-reporting
 * tokens, which is the safe direction.
 */
export function tokenizeSegments(command: string): Segment[] {
  const segments: Segment[] = [];
  let words: string[] = [];
  let cur = "";
  let has = false;
  let quote: '"' | "'" | null = null;
  let sepRun = "";
  let piped = false;

  const startWord = () => {
    if (has) return;
    has = true;
    if (words.length === 0) {
      piped = sepRun === "|" || sepRun === "|&";
      sepRun = "";
    }
  };
  const endWord = () => {
    if (has) words.push(cur);
    cur = "";
    has = false;
  };
  const endSegment = () => {
    endWord();
    if (words.length > 0) segments.push({ words, piped });
    words = [];
  };

  for (const ch of command) {
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      startWord();
      quote = ch;
    } else if (SEGMENT_BREAK.has(ch)) {
      endSegment();
      if (ch !== "\n" && ch !== "\r") sepRun += ch;
      else sepRun = "\n";
    } else if (REDIRECT.has(ch) || /\s/.test(ch)) {
      endWord();
    } else {
      startWord();
      cur += ch;
    }
  }
  endSegment();
  return segments;
}

/** The flat token list (the form `extractCandidates` consumes). */
export function tokenizeShell(command: string): string[] {
  return tokenizeSegments(command).flatMap((s) => s.words);
}

// ---------------------------------------------------------------------------
// Directory-search detection
// ---------------------------------------------------------------------------

export interface SearchRequest {
  /** The command that reads the tree (for the message). */
  tool: string;
  /** Raw directory tokens; empty means "the working directory". */
  dirs: string[];
  /** Positive file globs (a file must match one). Case-insensitive. */
  include: string[];
  /** Negative file globs (a matching file is skipped). */
  exclude: string[];
  /** File-type names to search (`ts`, `py`, …). */
  types: string[];
  typesNot: string[];
  /** The tool skips dot-files and dot-directories (ripgrep without --hidden). */
  skipHidden: boolean;
  /**
   * Which ignore files the tool honours by default (ripgrep): `vcs` is
   * `.gitignore` / `.git/info/exclude` / the global excludes file, `dot` is
   * `.ignore` / `.rgignore`. `grep -r`, `findstr /s` and PowerShell honour neither.
   */
  ignore: { vcs: boolean; dot: boolean };
}

const emptyRequest = (tool: string): SearchRequest => ({
  tool,
  dirs: [],
  include: [],
  exclude: [],
  types: [],
  typesNot: [],
  skipHidden: false,
  ignore: { vcs: false, dot: false },
});

/** `C:\tools\RG.exe` → `rg`. */
export function commandName(word: string): string {
  const base = word.slice(Math.max(word.lastIndexOf("/"), word.lastIndexOf("\\")) + 1);
  return base.toLowerCase().replace(/\.(?:exe|cmd|bat|ps1)$/, "");
}

const WRAPPERS = new Set([
  "sudo",
  "command",
  "env",
  "nohup",
  "time",
  "exec",
  "builtin",
  "noglob",
  "nice",
  "doas",
]);

/** Drop `FOO=bar` assignments and wrapper commands so the real command leads. */
function stripWrappers(words: string[]): string[] {
  let i = 0;
  while (i < words.length) {
    const w = words[i]!;
    if (/^[A-Za-z_][\w]*=/.test(w) || WRAPPERS.has(commandName(w))) {
      i++;
      // `sudo -u root grep …` / `env -i`: skip the wrapper's own flags.
      while (i < words.length && words[i]!.startsWith("-") && i > 0) {
        if (!WRAPPERS.has(commandName(words[i - 1]!))) break;
        i++;
      }
      continue;
    }
    break;
  }
  return words.slice(i);
}

interface ArgSpec {
  /** Short option letters that take a value. */
  short: string;
  /** Long option names (no dashes) that take a value. */
  long: ReadonlySet<string>;
}
interface Parsed {
  flags: Set<string>;
  values: Map<string, string[]>;
  positionals: string[];
}

/** A small POSIX/GNU-style option parser (short clusters, `--long[=value]`). */
function parseOptions(args: readonly string[], spec: ArgSpec): Parsed {
  const out: Parsed = { flags: new Set(), values: new Map(), positionals: [] };
  const addValue = (key: string, v: string) => {
    const list = out.values.get(key);
    if (list) list.push(v);
    else out.values.set(key, [v]);
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--") {
      out.positionals.push(...args.slice(i + 1));
      break;
    }
    if (a.startsWith("--") && a.length > 2) {
      const eq = a.indexOf("=");
      const name = eq >= 0 ? a.slice(2, eq) : a.slice(2);
      out.flags.add(name);
      if (eq >= 0) addValue(name, a.slice(eq + 1));
      else if (spec.long.has(name) && i + 1 < args.length) addValue(name, args[++i]!);
    } else if (a.startsWith("-") && a.length > 1 && !/^-\d+$/.test(a)) {
      for (let c = 1; c < a.length; c++) {
        const ch = a[c]!;
        out.flags.add(ch);
        if (spec.short.includes(ch)) {
          const rest = a.slice(c + 1);
          if (rest) addValue(ch, rest);
          else if (i + 1 < args.length) addValue(ch, args[++i]!);
          break;
        }
      }
    } else {
      out.positionals.push(a);
    }
  }
  return out;
}

const vals = (p: Parsed, ...keys: string[]) => keys.flatMap((k) => p.values.get(k) ?? []);
const has = (p: Parsed, ...keys: string[]) => keys.some((k) => p.flags.has(k));

const GREP_SPEC: ArgSpec = {
  short: "efmABCdD",
  long: new Set([
    "regexp",
    "file",
    "max-count",
    "include",
    "exclude",
    "exclude-from",
    "exclude-dir",
    "directories",
    "devices",
    "context",
    "after-context",
    "before-context",
    "label",
    "binary-files",
  ]),
};
const RG_SPEC: ArgSpec = {
  short: "ABCdefgjmMrtTE",
  long: new Set([
    "after-context",
    "before-context",
    "context",
    "max-depth",
    "regexp",
    "file",
    "glob",
    "iglob",
    "threads",
    "max-count",
    "max-columns",
    "replace",
    "type",
    "type-not",
    "type-add",
    "encoding",
    "sort",
    "sortr",
    "max-filesize",
    "ignore-file",
    "pre",
    "pre-glob",
    "colors",
    "engine",
    "path-separator",
  ]),
};

function grepRequest(args: string[], tool: string): SearchRequest | null {
  const p = parseOptions(args, GREP_SPEC);
  const recursive =
    has(p, "r", "R", "recursive", "dereference-recursive") ||
    vals(p, "d", "directories").includes("recurse");
  if (!recursive) return null; // a non-recursive grep names files; the path check covers those
  const patternGiven = has(p, "e", "regexp", "f", "file");
  const paths = patternGiven ? p.positionals : p.positionals.slice(1);
  return {
    ...emptyRequest(tool),
    dirs: paths,
    include: vals(p, "include"),
    exclude: vals(p, "exclude"),
  };
}

function rgRequest(args: string[], tool: string, piped: boolean): SearchRequest | null {
  const p = parseOptions(args, RG_SPEC);
  if (has(p, "files", "type-list", "help", "version", "V", "h")) return null; // does not read contents
  const patternGiven = has(p, "e", "regexp", "f", "file");
  const paths = patternGiven ? p.positionals : p.positionals.slice(1);
  if (paths.length === 0 && piped) return null; // searches stdin, not the tree
  const globs = vals(p, "g", "glob", "iglob");
  // `-u` lifts ignore files, `-uu` (or --hidden / -.) also searches dot-files.
  const unrestricted = args.reduce(
    (n, a) => n + (/^-u+$/.test(a) ? a.length - 1 : a === "--unrestricted" ? 1 : 0),
    0,
  );
  const hidden = has(p, "hidden", ".") || unrestricted >= 2;
  const noIgnore = has(p, "no-ignore") || unrestricted >= 1;
  // The finer-grained switches that stop a SUBSET of the VCS sources are treated as
  // "all VCS ignores off": we cannot tell the sources apart, and in scope is the safe side.
  const noVcs =
    noIgnore ||
    has(p, "no-ignore-vcs", "no-ignore-global", "no-ignore-exclude", "no-ignore-parent");
  const noDot = noIgnore || has(p, "no-ignore-dot");
  return {
    ...emptyRequest(tool),
    dirs: paths,
    include: globs.filter((g) => !g.startsWith("!")),
    exclude: globs.filter((g) => g.startsWith("!")).map((g) => g.slice(1)),
    types: vals(p, "t", "type"),
    typesNot: vals(p, "T", "type-not"),
    skipHidden: !hidden,
    ignore: { vcs: !noVcs, dot: !noDot },
  };
}

// --- findstr / cmd ----------------------------------------------------------

const HAS_WILDCARD = /[*?]/;

function findstrRequests(args: string[], tool: string): SearchRequest[] {
  const lower = args.map((a) => a.toLowerCase());
  if (!lower.includes("/s")) return [];
  const patternGiven = lower.some((a) => a.startsWith("/c:") || a.startsWith("/g:"));
  const positionals = args.filter((a) => !a.startsWith("/"));
  const specs = patternGiven ? positionals : positionals.slice(1);
  const out: SearchRequest[] = [];
  for (const spec of specs) {
    const norm = spec.replace(/\\/g, "/");
    const slash = norm.lastIndexOf("/");
    const dir = slash >= 0 ? spec.slice(0, slash + 1) : "";
    const name = slash >= 0 ? norm.slice(slash + 1) : norm;
    out.push({ ...emptyRequest(tool), dirs: dir ? [dir] : [], include: name ? [name] : [] });
  }
  return out;
}

// --- PowerShell -------------------------------------------------------------

interface PsParsed {
  named: Map<string, string[]>;
  switches: Set<string>;
  positionals: string[];
}

/** PowerShell parameters are case-insensitive and may be abbreviated; match by prefix. */
function canonicalParam(name: string, known: readonly string[]): string | null {
  const n = name.toLowerCase();
  if (n.length < 2) return null;
  return known.find((k) => k === n) ?? known.find((k) => k.startsWith(n)) ?? null;
}

function parsePowerShell(args: readonly string[], valueParams: readonly string[]): PsParsed {
  const out: PsParsed = { named: new Map(), switches: new Set(), positionals: [] };
  const add = (k: string, v: string) => {
    const list = out.named.get(k);
    const parts = v.split(",").filter(Boolean);
    if (list) list.push(...parts);
    else out.named.set(k, parts);
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    const m = /^-([A-Za-z]+)(?::(.*))?$/.exec(a);
    if (!m) {
      out.positionals.push(...a.split(",").filter(Boolean));
      continue;
    }
    const name = m[1]!;
    const canon = canonicalParam(name, valueParams);
    if (canon) {
      if (m[2] !== undefined && m[2] !== "") add(canon, m[2]);
      else if (m[2] === undefined && i + 1 < args.length) add(canon, args[++i]!);
    } else {
      out.switches.add(name.toLowerCase());
    }
  }
  return out;
}

const isRecurse = (switches: ReadonlySet<string>) =>
  [...switches].some((s) => s.startsWith("r") && "recurse".startsWith(s));

const SLS_PARAMS = [
  "pattern",
  "path",
  "literalpath",
  "include",
  "exclude",
  "context",
  "encoding",
  "culture",
  "inputobject",
];
const GCI_PARAMS = ["path", "literalpath", "filter", "include", "exclude", "depth", "attributes"];

function selectStringRequest(args: string[], tool: string): SearchRequest | null {
  const p = parsePowerShell(args, SLS_PARAMS);
  if (!isRecurse(p.switches)) return null; // wildcard paths are covered by the path check
  const paths =
    p.named.get("path") ??
    p.named.get("literalpath") ??
    p.positionals.slice(p.named.has("pattern") ? 0 : 1);
  return {
    ...emptyRequest(tool),
    dirs: paths,
    include: p.named.get("include") ?? [],
    exclude: p.named.get("exclude") ?? [],
  };
}

function childItemRequest(args: string[], tool: string): SearchRequest | null {
  const p = parsePowerShell(args, GCI_PARAMS);
  if (!isRecurse(p.switches)) return null;
  const paths = p.named.get("path") ?? p.named.get("literalpath") ?? p.positionals;
  return {
    ...emptyRequest(tool),
    dirs: paths,
    include: [...(p.named.get("filter") ?? []), ...(p.named.get("include") ?? [])],
    exclude: p.named.get("exclude") ?? [],
  };
}

const CHILD_ITEM = new Set(["get-childitem", "gci", "dir", "ls"]);
/** Commands that read the files a recursive listing feeds them. */
const PIPE_READERS = new Set([
  "select-string",
  "sls",
  "get-content",
  "gc",
  "cat",
  "type",
  "more",
  "foreach-object",
  "%",
]);

/**
 * Every directory-tree read in a Bash/PowerShell/cmd command line. Single-file
 * reads are NOT reported here — `extractCandidates` already treats every token as
 * a path.
 */
export function detectShellSearches(command: string): SearchRequest[] {
  const segments = tokenizeSegments(command);
  const out: SearchRequest[] = [];

  segments.forEach((seg, idx) => {
    const words = stripWrappers(seg.words);
    if (words.length === 0) return;
    const name = commandName(words[0]!);
    const args = words.slice(1);

    switch (name) {
      case "grep":
      case "egrep":
      case "fgrep":
      case "zgrep": {
        const r = grepRequest(args, name);
        if (r) out.push(r);
        return;
      }
      case "rg":
      case "ripgrep": {
        const r = rgRequest(args, name, seg.piped);
        if (r) out.push(r);
        return;
      }
      case "findstr":
        out.push(...findstrRequests(args, name));
        return;
      case "select-string":
      case "sls": {
        const r = selectStringRequest(args, name);
        if (r) out.push(r);
        return;
      }
      default:
        break;
    }

    if (CHILD_ITEM.has(name)) {
      // A recursive listing only matters when a reader consumes it downstream.
      let reads = false;
      for (let j = idx + 1; j < segments.length && segments[j]!.piped; j++) {
        const next = stripWrappers(segments[j]!.words);
        if (next.length > 0 && PIPE_READERS.has(commandName(next[0]!))) reads = true;
      }
      if (reads) {
        const r = childItemRequest(args, name);
        if (r) out.push(r);
      }
    }
  });
  return out;
}

// ---------------------------------------------------------------------------
// The Grep tool
// ---------------------------------------------------------------------------

/** Split a glob list on whitespace and top-level commas, expanding `{a,b}` braces. */
export function splitGlobs(glob: string): string[] {
  const parts: string[] = [];
  let cur = "";
  let depth = 0;
  for (const ch of glob) {
    if (ch === "{") depth++;
    else if (ch === "}") depth = Math.max(0, depth - 1);
    if ((/\s/.test(ch) || ch === ",") && depth === 0) {
      if (cur) parts.push(cur);
      cur = "";
    } else cur += ch;
  }
  if (cur) parts.push(cur);
  return parts.flatMap(expandBraces);
}

export function expandBraces(glob: string): string[] {
  const m = /\{([^{}]*)\}/.exec(glob);
  if (!m) return [glob];
  const [pre, post] = [glob.slice(0, m.index), glob.slice(m.index + m[0].length)];
  return m[1]!.split(",").flatMap((alt) => expandBraces(`${pre}${alt}${post}`));
}

/**
 * The Claude Code `Grep` tool: `path` (default: the cwd), `glob`, `type`. It runs
 * ripgrep with its default filtering and no option to lift it, so hidden and
 * ignored files are out of scope unless a `glob` names them.
 */
export function grepToolRequest(ti: Record<string, unknown>): SearchRequest {
  const globs = typeof ti.glob === "string" ? splitGlobs(ti.glob) : [];
  return {
    ...emptyRequest("Grep"),
    skipHidden: true,
    ignore: { vcs: true, dot: true },
    dirs: typeof ti.path === "string" && ti.path ? [ti.path] : [],
    include: globs.filter((g) => !g.startsWith("!")),
    exclude: globs.filter((g) => g.startsWith("!")).map((g) => g.slice(1)),
    types: typeof ti.type === "string" && ti.type ? [ti.type] : [],
  };
}
