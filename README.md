# repo-wrapped-sweep

Sweep a machine for plaintext secrets — private keys, `.env` backups, cookie jars, editor history,
coding-agent transcripts — group copies of the same secret into one finding, and see which are
expected stores and which are leaks. The same walk also reports the work that exists only on your
machine, the disk you can reclaim, your toolchain drift and your AI usage
([machine insights](#machine-insights)).

**Local-first.** Every command here works with no account. The raw secret never leaves the process:
not to disk (the baseline holds fingerprints and paths only), not to the network, not to stdout (a
masked preview shows at most the first and last two characters).

```bash
npx repo-wrapped-sweep            # sweep your home directory
npx repo-wrapped-sweep --quick    # only the high-risk locations
```

Node ≥ 20. No native modules, no runtime dependencies.

## Why not just `gitleaks dir`?

Raw scanning is commodity. This adds the parts around it:

1. **Fingerprint grouping** — one key copied into 140 editor-history files is **one finding with 140
   locations**, not 140 findings.
2. **Places scanners skip** — VS Code/Cursor local history, `~/.claude/projects/**/*.jsonl`,
   `~/.codex/sessions`, shell history, `*.bak` and dated backup folders.
3. **Expected vs leaked** — an encrypted `~/.ssh/id_ed25519` or a home-level `~/.aws/credentials` is
   the _expected_ place for a credential (one severity step down); the same key in
   `~/Documents/test_harness_backup/` or an agent transcript is a leak (one step up).

## Usage

```
repo-wrapped-sweep [scan] [options]

  --root <dir>        Directory to sweep (repeatable). Default: your home directory
  --quick             Only the high-risk locations (see below)
  --exclude <glob>    Skip matching files/folders (repeatable)
  --include-cloud     Also sweep all of OneDrive / iCloud (a redirected Documents/Desktop on
                      Windows is swept by default; online-only files are never opened)
  --no-default-excludes
                      Also walk installed-software trees (Program Files, extensions, package
                      caches, browser profiles) that a sweep skips by default
  --all               List low-severity findings too (folded into one summary line by default)
  --json              Print the report as JSON (schemaVersion 1) instead of a table
  --html <file>       Also write a self-contained HTML report
  --fail-on <level>   critical | high | medium | low | new | none   (default: high)
  --baseline <file>   Baseline path (default ~/.repo-wrapped/sweep-baseline.json)
  --no-update         Do not write the baseline after the run
  --concurrency <n>   Parallel readers (default 8)
  --progress          Print a running file count to stderr
  --quiet             No table (exit code only)
  --no-insights       No machine-insights summary after the table, and no insights block in an upload
```

**Exit codes:** `0` clean · `1` findings at/above `--fail-on` (or any NEW finding with
`--fail-on new`) · `2` run error.

### What is scanned

| Mode           | Scope                                                                                                    |
| -------------- | -------------------------------------------------------------------------------------------------------- |
| default        | your home directory                                                                                      |
| `--root <dir>` | exactly the directories you name (nothing else)                                                          |
| `--quick`      | editor history, agent transcripts, shell history, credential files, `~/.ssh`, `~/Downloads`, `~/Desktop` |

Always skipped: `node_modules`, `.git`, `.next`, `dist`, `build`, `.turbo`, `.venv`, `venv`,
`__pycache__`, `.cache`, `.pnpm-store`, `*.app` bundles, OS and package caches, and browser profile
folders. Lockfiles, minified bundles and sourcemaps are ignored; `.env.example`, `.env.sample` and
`.env.template` are always allowed. Symlinks are never followed.

**Installed software is skipped by default.** A full sweep of a developer machine used to report
hundreds of "secrets" that were test keys inside installed programs and package caches. These
directories are no longer entered (an explicit `--root` inside one is still walked):

| OS      | Skipped                                                                                                                                                                                        |
| ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Windows | `AppData/Local/{Programs,Microsoft,Google/Cloud SDK,Epic Games,GitHubDesktop/app-*}`, `AppData/Roaming/gcloud/logs`, every browser `User Data` folder, `scoop/{apps,buckets}`, `Program Files` |
| macOS   | `/Applications`, Homebrew `Cellar`/`Caskroom`, `~/Library/Application Support` — **except** the editors' `User/History` (VS Code, Insiders, VSCodium, Cursor, Windsurf)                        |
| All     | `~/go/pkg/mod`, `~/.cargo/registry`, `~/.rustup`, `~/.m2`, `~/.gradle`, `~/.nuget`, `~/.npm/_cacache`, `~/.vscode/extensions`, `~/.cursor/extensions`, any `site-packages`                     |

Editor history and agent transcripts are never skipped. `--no-default-excludes` walks all of the
above again (`node_modules`, `.git` and OS caches stay skipped).

**Precision rules** (a full sweep; an explicit `--root` is you asking for everything under it):

- **`path.env-file`** matches `.env`, `.env.*`, `*.env`, `env.json`, `*.env.json`, `*-env.json`,
  `*_env.json` and `env.*.json` — still confirmed by content. It no longer matches any `*env*.json`
  (`pyenv.json` and `direnv.json` in a scoop bucket were findings). A real env file with another name
  is still found by the content rules.
- **Test and vendor fixtures drop to low.** Any hit — path rules included — under a directory named
  `test`, `tests`, `__tests__`, `testdata`, `test_data`, `fixtures`, `third_party`, `vendor`,
  `dummyserver` or `examples` is a sample, not a leak. Editor history and agent transcripts are not
  downgraded by _their own_ path; a history snapshot is judged by the file it was a copy of (below).
- **`generic-secret-assignment`** (`password = "…"`) fires only in config-like files — `.env*`,
  `.json`, `.yaml`/`.yml`, `.toml`, `.ini`, `.properties`, `.conf`, `.config`, `.xml`, `*rc` dotfiles —
  and in shell history, agent transcripts and editor history, and never on a line over 1,000 characters
  (a minified bundle). Provider rules (`ghp_`, `sk_live_`, `AKIA`, `AIza`, PEM, …) still fire everywhere,
  on a line of any length.
- **VS Code local history.** Each `History/<id>/` directory has an `entries.json` naming the file its
  snapshots are copies of. The sweep reads it to recover that original path: a snapshot of
  `.env.example` is not a finding, a snapshot of `tests/fixtures/x.pem` is a fixture, and the report says
  "VS Code history of ~/proj/.env.prod" instead of `History/-6a9ea81e/9ya8.prod`. (`--json` carries both:
  `path` is the real file, for `fix`; `origin` is the original.)
- **Low findings are folded** into one line — "N low-severity findings not listed … run with --all" — in
  the table. `--all` lists them; `--json`, `--html`, `--fail-on` and uploads always see every finding.

Caps: files over 5 MB are skipped, except `*.jsonl` and shell-history files, which are streamed line
by line (64 KB per line). Files over 256 KB are scanned in overlapping line windows so a match never
straddles a cut.

**Cloud-sync folders** (`%OneDrive%`, `~/OneDrive*`, `~/Library/Mobile Documents`,
`~/Library/CloudStorage/*`) are skipped by default, because reading an online-only file forces a
download. The report says how many were skipped; `--include-cloud` sweeps all of them.

**Windows Known Folder Move.** With OneDrive "Known Folder Move", `Documents` and `Desktop` _are_
`~/OneDrive/Documents` and `~/OneDrive/Desktop`, so a cloud-skipping walk used to miss your documents
entirely. They are now swept, and **no online-only file is ever opened**: before reading a directory
inside a cloud-sync folder, the sweep asks Windows for each entry's file attributes
(`FILE_ATTRIBUTE_OFFLINE`, `RECALL_ON_OPEN`, `RECALL_ON_DATA_ACCESS`) from one long-lived PowerShell,
and skips anything that would download. If a directory's attributes cannot be read (no PowerShell, a
timeout, an error) that whole directory is skipped and counted — when unsure, never open. The same
check applies under `--include-cloud`. (Node's `fs` does not expose these attributes, hence the helper;
macOS and Linux have no such mode and keep the plain cloud skip.)

**Permissions.** Unreadable folders are counted and reported, never fatal. On macOS, grant your
terminal Full Disk Access to include protected folders.

### Baseline

After each run the sweep writes `~/.repo-wrapped/sweep-baseline.json`: fingerprints, rule ids, copy
counts and the home-relative paths of the copies — never the secret and never the preview. The next
run marks findings `NEW` and reports what is `GONE`; `--fail-on new` turns that into a CI gate. A
partial sweep (`--quick`, `--root`) refreshes what it saw but can't prove anything is gone.

### Configuration

`~/.repo-wrapped/sweep.json` (all keys optional):

```json
{ "exclude": ["*.log", "scratch"], "roots": ["~/code"], "hookAllow": [] }
```

### Fingerprints

`fingerprint = HMAC-SHA256(salt, normalizedSecret)`, first 16 bytes as hex. The salt is 32 random
bytes generated once into `~/.repo-wrapped/sweep-salt` (owner-only). A PEM key normalizes line
breaks, so the same key saved with CRLF, wrapped differently, or pasted into a transcript still
matches.

## Fix a finding

```bash
repo-wrapped-sweep fix <fingerprint>      # the first 6+ characters from a report are enough
```

One secret at a time, with a confirm before every destructive step:

1. **Store it properly** (optional) — hands the secret to the OS credential store (macOS Keychain,
   Windows Credential Manager, Linux `secret-tool`) under `repo-wrapped/<label>`, or prints an
   `op item create …` line for 1Password. _On macOS and Windows the value is passed as a command
   argument, so it is briefly visible in your own process list; it is never written to disk or
   printed. Linux passes it over stdin._ **`--yes` never skips this prompt.**
2. **Remove the copies** — moved to the OS **Trash / Recycle Bin, never deleted**. Only files that
   exist to hold a secret are moved (key files, `.env` files, cookie jars, service-account JSON,
   editor-history copies, backups); editor-history copies are offered as one batch. A source file
   with the token inline, a shell history, an agent transcript or an expected store like
   `~/.aws/credentials` is **listed for you to edit** — deleting those would destroy far more than
   the secret. `--yes` skips only the Trash prompts.
3. **Rotate** — prints the provider's rotation link. Rotation is always your action; the tool never
   calls a provider to revoke a key.
4. **Re-sweep** the affected paths and mark the fingerprint resolved in the baseline (exit `0`), or
   say what is left (exit `1`).

With no terminal (CI, a pipe) every prompt answers **no**, so nothing is moved on a guess.

## Is the key still live? (`--validate`)

```bash
repo-wrapped-sweep --validate
```

Asks each recognised key's **own provider** whether it still works — GitHub (`GET /user`), Anthropic
and OpenAI (`GET /v1/models`), Stripe (`GET /v1/balance`), Slack (`auth.test`) — and ranks live keys
first. 5-second timeout, one attempt, nothing logged; AWS keys and private keys are reported
`unknown`. A one-line warning is printed before the first call because **this is the one thing the
tool does that sends a secret anywhere.** It is interactive only: `--validate` is refused with
`--scheduled`, and neither the daily schedule nor an MDM-driven run ever validates.

## Machine insights

The same walk that finds secrets also answers the questions you ask when a laptop dies, a disk fills
or a repo won't build. **Every command here is local and read-only** — no account, no network (no
`git fetch` unless you pass `--fetch`) — except `disk clean`, which is the only command in the tool
that changes your machine, and `wrapped --share`, which is the only one that publishes anything.

```bash
repo-wrapped-sweep insights            # git + disk + toolchain + backup in one pass
repo-wrapped-sweep git [--fetch] [--all]
repo-wrapped-sweep disk
repo-wrapped-sweep disk clean [--yes] [--older-than 30d] [--include-venv] [--include-npm-cache] [--dry-run]
repo-wrapped-sweep toolchain [--all]
repo-wrapped-sweep backup [--all]
repo-wrapped-sweep ai [--since 30d|YYYY-MM-DD] [--by repo|day|model] [--json]
repo-wrapped-sweep wrapped [--year 2026] [--out card.html] [--png] [--share]
```

The first five take `--root`, `--exclude`, `--include-cloud`, `--concurrency`, `--json` and
`--html <file>`; a full interactive sweep prints a three-line summary of them after the findings table
(`--no-insights` hides it).

| Command     | What it tells you                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `git`       | Clones with work that exists **only on this machine**: commits on no remote, no remote at all, uncommitted changes, stashes older than 30 days, a branch far behind. "Behind" is as of the last fetch — labelled so; `--fetch` fetches first. Worst first.                                                            |
| `disk`      | Regenerable build output and caches by size — `node_modules`, `.next`/`.turbo`/`.nuxt`/`.svelte-kit`, Rust `target`, Python caches, Gradle `build`, package-manager caches — and how much sits in projects untouched for 30+ days. Docker is reported, never cleaned. `dist/` and `out/` are reported, never cleaned. |
| `toolchain` | Installed runtimes and CLIs (local `--version` probes, 2 s each) against what each repo pins (`.nvmrc`, `engines`, `packageManager`, `.python-version`, `.tool-versions`, `rust-toolchain`, `go.mod`, `global.json`). `node 20.11 installed, .nvmrc wants 22 → run "fnm use"`.                                        |
| `backup`    | Project folders that are neither in a synced folder (OneDrive, iCloud, Dropbox) nor pushed: `synced`, `pushed`, `partly-pushed`, `local-only`.                                                                                                                                                                        |
| `ai`        | Claude Code and Codex sessions, tokens, models and **API-equivalent cost** per repo, day or model.                                                                                                                                                                                                                    |
| `wrapped`   | The year on this machine as a self-contained dark-first HTML card (commits, languages, AI sessions and share, busiest day and hour, streak). `--png` also screenshots it with a Chrome/Edge already installed.                                                                                                        |

### `disk clean`

Deletes the regenerable folders `disk` listed. Every rule is tested:

- **Dry run by default.** It prints exactly what would go and the total; `--yes` acts. At a terminal
  without `--yes` it asks per project; with no terminal (CI, a pipe, `--json`) it is a dry run.
- Only the classes `disk` lists, only **next to the file that rebuilds them** (a lockfile beside
  `node_modules`, `Cargo.toml` beside `target`, …), only in projects untouched for `--older-than`
  (default 30 days). Never `dist/`, `out/`, `.venv` (unless `--include-venv`), Docker, or anything
  outside your home.
- Never follows a symlink or junction, refuses a target whose real path leaves its project, refuses
  a folder git tracks or sees changes in, and re-proves each target from a fresh listing just before
  deleting it.
- Package caches use the tool's own prune (`pnpm store prune`, `yarn cache clean`, `pip cache purge`;
  `npm cache clean --force` only with `--include-npm-cache`) — never `rm`.
- Deletion is **permanent** (not to the Trash — moving gigabytes of `node_modules` to the bin reclaims
  nothing until it is emptied), and every action is appended to `~/.repo-wrapped/clean-log.jsonl`
  (`path`, `bytes`, `time`).
- It refuses `--scheduled`: the daily schedule and an MDM-driven run can never delete anything.

### AI usage

`ai` reads token counts, model ids, timestamps and the working directory of each session from
`~/.claude/projects/**/*.jsonl` and `~/.codex/sessions/**/*.jsonl` (plus archived and `.zst`-compressed
Codex rollouts on Node 22.15+) — **never message text, prompts or code**; a test plants a sentinel in
every text field and greps the output. Lines over 64 KB are skipped (about 0.3 % of tokens). It is
incremental (`~/.repo-wrapped/ai-cursor.json`), de-duplicates repeated and resumed-session lines, and
attributes each session to the nearest repo from its working directory.

**Cost is "API-equivalent":** what the same tokens would cost on the pay-as-you-go API, from a pinned
price table whose date (`pricesAsOf`) every report shows. It is **not** a bill — Pro, Max and Team
subscribers are not charged it. A model with no known price is listed as unpriced, its tokens counted
and its cost left out.

### Share your Machine Wrapped (optional, Pro)

```bash
repo-wrapped-sweep wrapped --year 2026 --share
```

`--share` publishes **that year's aggregate card** as a section of your public Contributor Wrapped at
`repowrapped.com/dev/<your-login>`. It is opt-in per year — nothing is shared unless you run it, one
year per run, and running it again replaces that year. What goes up: commit and repo **counts**,
language **shares**, session / active-hour / token totals, API-equivalent cost, the top model's id,
busiest weekday and hour, streak. What never does: repo names, folder names, paths, your email, commit
hashes or messages, prompts. (It holds no names at all, so `--share-paths` changes nothing here.) The
server rejects a body with any field the card has no place for.

It needs an enrolled **personal** device on a Pro account — a machine that reports to an organization
cannot publish to a personal profile — and a terminal: it is refused from a schedule, and where your
administrator set `insights: false`. If you have not generated your Contributor Wrapped yet the card
is stored and appears once you do. **Unpublish** any time from Workspace → Endpoints → Machine, or by
deleting your account.

## Optional account: enrol and upload

Everything above works with no account. To see findings across your laptops (or your organization's)
in Repo Wrapped:

```bash
repo-wrapped-sweep enrol <token>     # Workspace → Endpoints → Add device (rwd_…) or an org admin's rwo_…
repo-wrapped-sweep enrol <token> --share-repo-names   # optional: show repo names, not ids
repo-wrapped-sweep --upload
```

An upload is **metadata only**: per finding, a salted fingerprint, a masked preview (at most four
characters of the secret), how many copies and in which _kinds_ of place (editor history, agent
transcripts, …). The CLI refuses to upload anything whose preview isn't mask-shaped, and the server
rejects it too. **Paths are not uploaded** unless the enrolment says so — `enrol --share-paths` for a
personal device, or the admin's choice on an org token — and then only home-relative (`~/…`), never
your username. The enrol command prints the setting so you always know.

**Machine insights ride the same upload** (schema v2): an `insights` block with OS version, CPU and
disk totals, counts of repos by git state, reclaimable gigabytes by class, tool versions and
version-pin mismatches, backup counts and per-day AI usage since the last accepted upload. Counts,
sizes, versions, timestamps, model ids and token totals — **no file, prompt, code or message
content.** A repo travels as a salted id (`HMAC(salt, normalized remote URL)`, so two clones of one
repo match, and the server cannot reverse it). A readable name travels only on opt-in, enforced by
the server too: **repo names** (`owner/repo` from the remote, or the folder's own name — never a
path) with `enrol --share-repo-names` or the device's **Repo names** toggle in the site's Devices
table (the CLI reads that setting before each upload), or the home-relative path with
`--share-paths`. With repo names on, uploads also carry a small id → name directory of every repo
the sweep saw, so AI usage uploaded before you turned it on gets names too; turning it off clears
the stored names. `--no-insights` — or `"insights": false` in the MDM config — sends the unchanged
v1 body instead, and a server that predates v2 still accepts it.

Enrolling swaps the local fingerprint salt for the organization's (or your account's) so the same key
on five machines groups into one finding; your local baseline is reset because its fingerprints no
longer apply. `~/.repo-wrapped/device.json` (owner-only) holds the device token and salt.

**MDM / fleet rollout.** Drop `{ "enrolToken": "rwo_…", "upload": true, "schedule": true }` at
`/Library/Application Support/RepoWrapped/sweep.json` (macOS) or `%ProgramData%\RepoWrapped\sweep.json`
(Windows); the CLI enrols itself on first run and installs the daily schedule. Add
`"insights": false` to keep the machine-insights block (and `wrapped --share`) off that fleet.

## Daily schedule

```bash
repo-wrapped-sweep schedule install --daily [--upload]
repo-wrapped-sweep schedule status
repo-wrapped-sweep schedule uninstall
```

A macOS LaunchAgent (`com.repowrapped.sweep`), a Windows scheduled task (`RepoWrappedSweep`) or a
systemd **user** timer, running `--quiet --scheduled [--upload]` at a stable per-machine time between
09:00 and 15:00. With `--upload` the scheduled run sends the machine-insights block with the findings
(unless `--no-insights` or MDM `insights: false`); without it nothing leaves the machine. A scheduled
run can **never** `disk clean`, `--validate` or `wrapped --share` — each refuses `--scheduled`.
**macOS:** a LaunchAgent cannot read `~/Documents`, `~/Desktop` or `~/Downloads`
without Full Disk Access — the installer probes for it and, if blocked, prints the exact System
Settings path and the binary to add.

## Agent guard (Claude Code)

The same rules can stop a coding agent from reading a secret in the first place — before it lands in
a transcript:

```bash
repo-wrapped-sweep hook install              # ~/.claude/settings.json  (or --scope project)
repo-wrapped-sweep hook status
repo-wrapped-sweep hook uninstall            # removes only this tool's entry
```

`install` merges a `PreToolUse` hook (`Read|Bash|PowerShell|Grep|Edit|MultiEdit|NotebookEdit` →
`repo-wrapped-sweep hook check`) into the settings file without touching your other hooks or keys, and
is idempotent. Re-running it after an upgrade rewrites our entry's matcher in place (so an older
`Read|Bash|Grep|Edit` entry picks up the new tools); a file it can't parse as JSON is left alone.

`hook check` denies (exit 2, one-line reason on stderr) when a tool call touches:

- a private key (`.pem`/`.key`/`.p8`/`id_*`, confirmed by a 4 KB header probe — a certificate is
  fine), a `.p12`/`.pfx`, a `.env`/`.env.*` file, a cookie jar, or a service-account JSON;
- a home-level credential file (`~/.aws/credentials`, `~/.npmrc`, `~/.docker/config.json`) or a
  `.netrc` / `.git-credentials` / `.kube/config`;
- any file a previous sweep recorded in the baseline.

For Bash and PowerShell it tokenizes the command (quotes, pipes, redirects, `$HOME`/`~`/`%USERPROFILE%`/
`$env:USERPROFILE`, `.env*` wildcards, comma lists, `-Path:value`) and tests every path-like token, so
`type`, `Get-Content`/`gc`/`cat`, `Select-String`/`sls`, `more` and `findstr` are all covered. Paths are
normalized before they are checked: resolved against the call's working directory, backslashes and
forward slashes treated alike, drive letters and Git Bash/WSL spellings (`/c/Users`, `/mnt/c/Users`)
understood, and — on Windows and macOS — compared case-insensitively (`.env.` and `.env::$DATA` count
as `.env`). `.env.example` / `.env.sample` / `.env.template` are always allowed. Malformed input
**fails open** — a bug in the guard never blocks the agent. To let a path through, add a glob to
`hookAllow` in `~/.repo-wrapped/sweep.json`.

### Directory searches

A recursive search reads every file under a directory, so one `.env` three folders down defeats a
per-path check. `hook check` therefore also refuses these when the directory holds a credential file:

- the `Grep` tool (its `path`, or the working directory when absent);
- `grep -r`/`-R`/`--recursive`, `rg`, `findstr /s`, `Select-String … -Recurse`, and a recursive
  `Get-ChildItem` piped into `Select-String`/`Get-Content`;
- a wildcard such as `cat dir/*` or `Get-Content dir\*`.

It looks for the files with a **bounded** walk — at most 4 levels deep and 2,000 directory entries, with
the same excludes as the sweeper (`node_modules`, caches, `.git`, nested cloud-sync folders, the
`exclude` list in `sweep.json`), never following links. If the entry bound is hit, only the baseline's
recorded locations are used, so the answer never depends on directory order. The denial names up to three
of the flagged files and suggests a narrower path or an exclusion (`rg --glob '!.env'`, `grep
--exclude=.env`, a `Grep` glob of `!.env`). A search is **allowed** when its own filter provably excludes
every flagged file — a `glob`/`--include`/`--exclude`/`-g` or a `type`/`-t` that cannot match them.

**The rule: the guard blocks searches that would actually read a flagged file under the tool's own
default filtering.** The `Grep` tool and `rg` run ripgrep, which skips hidden files (any path segment
starting with `.`) and anything its ignore files list; a flagged file it would skip is out of scope. So a
gitignored `.env.local` — present in nearly every Next.js repo — does not block `Grep {"pattern":"foo"}`
or `rg foo`. The filtering is lifted only by what lifts it in ripgrep:

- hidden files come back with `rg --hidden` / `-.` / `-uu` / `-uuu`;
- ignored files come back with `rg --no-ignore` / `-u` (all ignore files), `--no-ignore-vcs` (and
  `-global`/`-exclude`/`-parent`, treated as lifting every `.gitignore` source — the safe side),
  `--no-ignore-dot` (`.ignore`/`.rgignore` only);
- an explicit glob that matches the file (`Grep` `glob: ".env.local"`, `rg -g '*.local'`) whitelists it, as in
  ripgrep, and beats both filters.

Ignore status is decided for the **flagged candidates only**, never the tree: `.ignore`/`.rgignore` by a
simple gitignore-syntax glob match (nearest file wins, `.rgignore` over `.ignore`, `!` negations), and
`.gitignore` (plus `.git/info/exclude` and the global excludes file) by **one** `git check-ignore --no-index
--stdin -z` spawn per call, only inside a git work tree (the nearest `.git` upward, bounded). Outside a
repository there is no gitignore filtering. If `git` is missing, errors or takes longer than its deadline (150 ms on
Windows, 30 ms elsewhere) the file stays **in scope** — the guard fails toward blocking, and the denial ends
with why (`could not confirm .gitignore — git check-ignore timed out` or `… git unavailable`).

A **direct** read is never filtered: `Read`, `cat`, `type`, `Get-Content`, a `Grep` whose `path` _is_ the
file, or `rg foo .env.local` stay denied, because ripgrep searches an explicitly named file whatever the
ignore rules say. And the tools that filter nothing — `grep -r`/`-R`, `findstr /s`, `Select-String -Recurse`,
`cat dir/*`, `Get-ChildItem -Recurse | Select-String` — are denied exactly as before, hidden and ignored
files included. A backup copy of an environment file (`env.bak`, `prod.env.old`) counts as an environment
file.

### What this is not

The hook is a **guard rail, not a sandbox.** It reads the arguments of a tool call; it cannot see what a
program does with them. Reads that happen _inside an interpreter or script_ are not caught — `node -e`,
`python -c`, a shell script, `make`, `find … -exec`, `xargs`, a build tool that dumps its environment.
It also cannot follow `cd` between commands, expand variables it does not know, or see a path assembled
at run time. Treat it as a way to stop the accidental read, and keep real secrets out of reach with
`repo-wrapped-sweep fix`.

Only Claude Code has a documented pre-tool hook contract; other agents are not covered.

## Development

```bash
pnpm install --ignore-workspace
pnpm test        # vitest
pnpm typecheck
pnpm build       # tsup → dist/index.js
```

The CLI **bundles** the pure scanner modules from the app (`src/lib/native-scan/*`) — it never forks
them. A test asserts the bundle contains exactly the app's `SECRET_RULES`.

## Source and releases

This public repository, [`PouriahLabs/repo-wrapped-sweep`](https://github.com/PouriahLabs/repo-wrapped-sweep),
is a **mirror**: the CLI is developed inside the Repo Wrapped monorepo, where it shares its rules with the
web app's scanners. Each release rebuilds this repo from there (the shared modules live under
`vendor/src/lib`). Issues are welcome here; code changes are ported upstream.

Releases are published to npm by `.github/workflows/publish.yml` on a `v*` tag, using npm trusted
publishing — no long-lived npm token exists — with provenance you can check:

```sh
npm audit signatures            # in a project that depends on repo-wrapped-sweep
```
