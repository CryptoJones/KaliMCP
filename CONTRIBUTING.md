# Contributing to KaliMCP

Thanks for taking a look. KaliMCP is a small, focused project: an MCP
server that wraps a curated set of Kali Linux security tools and audit-
logs every call. Contributions that add a well-scoped tool wrapper,
tighten the audit/redaction story, or fix a bug are all welcome.

## Mirrors

KaliMCP lives on two forges:

- GitHub: <https://github.com/CryptoJones/KaliMCP>
- Codeberg: <https://codeberg.org/CryptoJones/KaliMCP>

Issues and pull requests on **either** are read. Commits land on both —
if you send a PR to one mirror, that's fine; the maintainer reconciles
the other.

## Dev setup

```bash
git clone https://github.com/CryptoJones/KaliMCP.git
cd KaliMCP
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

You do **not** need the wrapped binaries (nmap, hydra, …) installed to
develop or run the test suite — `kalimcp.run.run` is patched in the
unit tests, so nothing spawns a real subprocess. You only need the real
tools to run `scripts/smoke_client.py` end-to-end.

## Before you push

Both gates run in CI (Woodpecker + GitHub Actions) against Python 3.11
and 3.12. Run them locally first:

```bash
.venv/bin/ruff check .          # lint
.venv/bin/python -m pytest -q   # tests (KALIMCP_NO_LOG is handled per-test)
```

Keep both green. New behavior needs a test.

## Adding a tool wrapper

Each wrapped CLI is one module under `src/kalimcp/tools/`. The pattern
(see `tools/nikto.py` for a clean example):

1. Write an `async def` decorated with `@active_tool(tool_name="…")`
   from `tools/_active.py`. It must take `target` as a keyword arg.
2. Build the `argv` list and hand it to `await run.run(argv, timeout=…)`.
   Never build a shell string — `run.run` uses `exec`, not a shell, so
   there is no injection surface as long as you pass a list.
3. Where it makes sense, parse the tool's stdout into a `parsed` dict
   so the agent gets structured data (operators still read raw stdout).
4. If the command line carries a secret (password, hash, cred file),
   pass `secret_flags={"-p", "--password", …}` to `@active_tool` so the
   audit log redacts the value to `sha256:<8hex>`.
5. Register it in `src/kalimcp/server.py` as a thin `@mcp.tool()` that
   delegates to your wrapper.
6. Add an argv-contract test in `tests/test_tools.py` and a registration
   assertion in `tests/test_server.py`.
7. If it needs a binary, add the apt package to the `Dockerfile`.

There is intentionally **no refuse list** — declaring scope is the
operator's job. Don't add hard-coded target blocking; the audit log and
the engagement `scope` warning are the accountability mechanisms.

## Conventions

- Every source file starts with the SPDX header:
  `# SPDX-License-Identifier: Apache-2.0` / `# Copyright 2026 Aaron K. Clark`.
- Commits follow a conventional-ish style with a scope, e.g.
  `feat(tools): …`, `fix(audit): …`, `docs(readme): …`, `test(tools): …`.
- Target Python is 3.11+. Ruff config lives in `pyproject.toml`.

## License

By contributing you agree your contribution is licensed under the
project's [Apache 2.0](LICENSE) license.

---

Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/
