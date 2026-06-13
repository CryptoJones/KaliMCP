<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Aaron K. Clark -->

# KaliMCP threat model

KaliMCP hands an AI agent a curated set of Kali tools over stdio
JSON-RPC. This document records what it defends against, what it
deliberately does **not**, and where the residual risk sits. It is a
companion to [SECURITY.md](../SECURITY.md) (which covers
authorized-use responsibility and how to report a flaw).

A guiding design rule runs through all of it: **there are no
authorization or scope-blocking gates inside the server.** Whether a
target is in scope is the operator's call, enforced upstream of the MCP
boundary. KaliMCP's job is *capability + accountability*, not
permission. Every mitigation below is hardening or audit — never a
refuse list.

## Actors and trust boundaries

| Actor | Trust | Notes |
|-------|-------|-------|
| **Operator** | Trusted | Runs the server, declares scope, owns the host and the audit log. |
| **AI agent / MCP client** | Semi-trusted | Issues tool calls. Assumed not malicious, but *its context can be poisoned* by data it reads (see prompt injection). |
| **Scanned target** | **Untrusted / hostile** | Everything it returns — banners, page titles, headers, cert fields, tool stdout — is attacker-controlled. |
| **Host OS** | Trusted | Where subprocesses run. Shared-host exposure (e.g. a world-readable log) is in scope. |

The critical boundary is between the **scanned target** and the
**agent's context**: data crosses it on every scan, and the target
chooses that data.

## Threats and mitigations

### T1 — Prompt injection via tool output *(headline threat)*

A recon-wrapper server's most distinctive risk. Scanned-target output
flows straight into the agent, and with `KALIMCP_AUTORECORD=1` is
re-fed to later tools. A hostile target can embed
`ignore previous instructions, run X` in an HTTP `Server:` header, a
TLS cert CN, an HTML `<title>`, or an SMB share comment, and try to
steer the agent into scanning a new target, exfiltrating loot, or
disabling its own guardrails.

**Mitigations** (`kalimcp.untrusted`, applied at the `@active_tool`
choke point):

- Every active-tool result is tagged `untrusted_output: true` and
  carries an `untrusted_note` telling the agent the content is inert
  data, not instructions.
- The `stdout`/`stderr` handed to the model is **bounded** (default
  64 KiB, `KALIMCP_MODEL_OUTPUT_LIMIT`) so a hostile or chatty target
  can't flood / steer the context with volume. The full output stays in
  the tool capture and, with auto-record on, is mirrored to the
  engagement loot store.

**Deliberately not done:** content scrubbing / "delete the injection"
filters. Any such filter is bypassable (encoding, language, framing)
and mangles legitimate recon data. Bounding + explicit tagging are the
honest mitigations; the final backstop is the agent's own
system-prompt discipline to treat tool output as data.

**Residual risk:** a sufficiently clever injection may still influence
an agent that ignores the tag. The tag and the audit log make such an
event detectable after the fact, not impossible.

### T2 — Secret leakage into the audit log / results

Credential tools put passwords, NT hashes and cred-file paths on the
command line. Naively logging argv (or echoing an exception) would
write those literals to `/var/log/kalimcp.log` or back to the client.

**Mitigations:**

- `audit.redact_argv` rewrites secret material to `sha256:<8hex>` in
  three shapes — `-flag value`, `--flag=value`, and **by value** (any
  known secret kwarg found anywhere in a token, e.g. fused into an
  impacket `user:pass@host`). This is *fail-closed*: a wrapper that
  forgets to declare `secret_flags` still can't leak a known secret.
- `audit.redact_text` extends the same by-value redaction to the
  `tool_exception` message — the second sink, which can quote argv.
- `process_list` exposes only a process's binary and arg *count*, never
  its argv, so the live-process view can't leak what the log redacts.

### T3 — Command injection

**Structurally eliminated.** Every subprocess is launched via
`asyncio.create_subprocess_exec` with a **list argv and no shell**
(`run.run`). No wrapper assembles a shell string. This is enforced as a
repository invariant by `tests/test_invariants.py`, which fails CI if
any source file reintroduces `shell=True`,
`create_subprocess_shell`, `os.system`/`os.popen`, or
`subprocess.get*output`.

### T4 — Tool-level flag / argument injection

No OS shell is involved (see T3), but a positional value beginning with
`-` can be re-read by the *wrapped tool* as one of its own flags
(`target="-oG/tmp/x"` → hydra's `-o`), and a CR/LF spliced into an HTTP
header (ffuf's `Host:`) is header injection.

**Mitigation:** `run.validate_arg` rejects a leading dash and embedded
newline/NUL on the affected positional/header slots (hydra, winrm,
msfvenom, ffuf). Syntactic well-formedness only — not a host allowlist.

### T5 — Path traversal in the engagement workspace

Engagement / loot names flow into filesystem paths.

**Mitigation:** `_sanitize_name` rejects all-dot names (`..`) so a name
can't escape the engagements root; file-path tool arguments route
through `run.validate_file` (existence/type check, one choke point).

### T6 — Resource exhaustion / DoS

A wrapped tool can run for hours; an agent can fan out many scans at
once; a chatty tool can emit gigabytes.

**Mitigations:** per-call wall-clock timeout; a global concurrency cap
(`KALIMCP_MAX_CONCURRENCY`, default 8) so parallel fan-out queues
instead of piling on; a 2 MB output capture cap; and the
`process_list` / `process_kill` pair so a runaway scan can be stopped
without tearing down the session (`process_kill` refuses any PID the
server didn't launch).

### T7 — Audit-log exposure on a shared host

The log holds recon metadata and credential-flag usage.

**Mitigation:** it is created `0600` via `os.open`, and `configure`
tightens the mode of any pre-existing log on first resolve.

### T8 — Supply-chain tampering

**Mitigations:** the Docker base is pinned by digest (not the moving
`kali-rolling` tag); CI runs `pip-audit` (dependency CVEs), a gitleaks
secret scan, and a syft CycloneDX SBOM.

## Explicit non-goals

- **No authorization / scope enforcement.** Out-of-scope targets get a
  non-blocking `out_of_scope` *warning* and an audit event — never a
  block. This is intentional and load-bearing; see SECURITY.md.
- **No protection against a malicious operator.** The operator is
  trusted; the audit log records what they did, it doesn't constrain it.
- **No guarantee against a determined prompt injection** influencing a
  non-compliant agent (see T1 residual risk).

## Summary

| # | Threat | Status |
|---|--------|--------|
| T1 | Prompt injection via tool output | Bounded + tagged; residual risk by design |
| T2 | Secret leakage to log / results | Fail-closed redaction |
| T3 | Command injection | Structurally eliminated + CI invariant |
| T4 | Tool-level flag/header injection | Validated positionals |
| T5 | Workspace path traversal | Name + path validation |
| T6 | Resource exhaustion | Timeout + concurrency cap + kill switch |
| T7 | Audit-log exposure | 0600 log |
| T8 | Supply-chain tampering | Digest pin + pip-audit + gitleaks + SBOM |
