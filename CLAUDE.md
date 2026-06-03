# CLAUDE.md

Guidance for AI agents working in this repository.

## What this is

KaliMCP is an [MCP](https://modelcontextprotocol.io/) server that
exposes a curated subset of Kali Linux security tools (nmap, hydra,
sqlmap, the impacket suite, …) to an AI agent over stdio JSON-RPC.
Every tool call is audit-logged. It is packaged as `kalimcp` and ships
as a Kali-based Docker image.

## Commands

```bash
.venv/bin/pip install -e '.[dev]'   # dev install
.venv/bin/python -m pytest -q       # tests (no real subprocesses spawn)
.venv/bin/ruff check .              # lint — CI gate
docker build -t kalimcp .           # build the runtime image
python scripts/smoke_client.py      # manual end-to-end smoke (needs real binaries)
```

CI (`.woodpecker.yml` + `.github/workflows/test.yml`) runs ruff and
pytest on Python 3.11 and 3.12, plus a hadolint pass on the Dockerfile.

## Architecture

Request flow: MCP client → `server.py` (`@mcp.tool()` registration) →
a wrapper in `tools/` → `run.run()` (subprocess) → structured dict back
up. Cross-cutting concerns (audit log, scope warning, auto-record) live
in the `@active_tool` decorator, not in each wrapper.

- `src/kalimcp/server.py` — FastMCP entry point. Each `@mcp.tool()` is a
  thin async shim that delegates to a `tools/` wrapper. This is the only
  file that knows about MCP.
- `src/kalimcp/tools/_active.py` — the `active_tool` decorator. Wraps a
  scan coroutine to: time it, append a `tool_invoke` audit line (with
  secret-redacted argv), emit a non-blocking `out_of_scope` warning when
  the active engagement has a scope the target misses, and (when
  `KALIMCP_AUTORECORD=1`) mirror `result["parsed"]` into the engagement
  workspace. There is **no refuse list** — it was removed deliberately.
- `src/kalimcp/tools/*.py` — one module per wrapped CLI. Each builds an
  `argv` list, calls `run.run`, and usually distills stdout into a
  `parsed` dict. `tools/passive.py` holds the non-decorated lookups
  (whois/dig/searchsploit/cert) that don't probe the target and log a
  `passive_invoke` event instead.
- `src/kalimcp/run.py` — the only place subprocesses launch. Uses
  `asyncio.create_subprocess_exec` (a list argv, **no shell**), a hard
  timeout, and a 2 MB output cap. Missing binaries raise
  `ToolNotInstalled`.
- `src/kalimcp/audit.py` — JSONL audit log. Strict side channel: it
  never raises and never affects tool execution. `redact_argv` rewrites
  secret-flag values to `sha256:<8hex>`. `KALIMCP_NO_LOG=1` disables it.
- `src/kalimcp/engagement.py` — per-engagement working memory under
  `~/.kalimcp/engagements/<name>/` (findings/creds/loot/notes + scope
  matching). Pure filesystem I/O; best-effort (write failures return
  `False`, never raise).

## Conventions / gotchas

- Build `argv` as a **list** and pass it to `run.run`. Never assemble a
  shell string — that would reintroduce a command-injection surface.
- If a command line carries a secret, pass `secret_flags={...}` to
  `@active_tool` so the audit log redacts it. Test that it's redacted.
- The audit log is forensic ground truth; the engagement workspace is a
  convenience mirror. Don't make tool behavior depend on the workspace.
- Every source file starts with the SPDX / copyright header.
- Adding a tool? See `CONTRIBUTING.md` for the full wrapper checklist
  (wrapper → register in `server.py` → test → Dockerfile apt line).
- Tests never hit the network or spawn real tools — `run.run` is
  patched. Keep new tests that way.
