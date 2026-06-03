# Security Policy

KaliMCP exposes offensive security tooling to an AI agent. Two very
different classes of "security issue" can arise, and they are handled
differently.

## 1. Authorized use — the operator's responsibility

KaliMCP does **not** enforce a hard-coded refuse list. It will scan,
brute-force, or inject against whatever target it is pointed at. The
operator is solely responsible for only using it against systems they
are authorized to test: pentest engagements with written scope, CTFs,
their own lab, or bug-bounty programs whose scope covers the target.

The accountability mechanism is the audit log: every invocation
appends one JSON line (tool, target, argv, exit code, elapsed time) to
`/var/log/kalimcp.log` (or `~/.kalimcp/kalimcp.log`). Credential
literals in argv are redacted to `sha256:<8hex>`. An active engagement
with a declared `scope` emits a non-blocking `out_of_scope` warning for
off-scope targets. None of this is a substitute for authorization — it
is a record that you had it.

Using these tools without authorization is a federal-grade mistake and
is not a bug in KaliMCP.

## 2. Vulnerabilities in KaliMCP itself

If you find a flaw in the **server code** — for example a command
injection in a tool wrapper, an argv path that leaks a redacted secret
into the audit log, a sandbox escape, or a way to make the server run a
binary it shouldn't — please report it.

- **Preferred:** email **akclark@thenetwerk.net** with details and, if
  possible, a minimal reproduction. Please do not open a public issue
  for an unpatched code-execution or secret-leak class bug.
- Lower-severity hardening ideas can go straight to a tracking issue on
  either mirror ([GitHub](https://github.com/CryptoJones/KaliMCP/issues)
  or [Codeberg](https://codeberg.org/CryptoJones/KaliMCP/issues)).

There is no bug-bounty program. Expect a best-effort, hobby-project
response time.

## Supported versions

KaliMCP is pre-1.0 (`Development Status :: 3 - Alpha`). Only the latest
tagged release on `main` receives fixes; there are no backport branches.

---

Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/
