# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""Engagement workspace — the agent's working memory across calls.

Every active engagement is a directory under
``~/.kalimcp/engagements/<name>/``:

    engagement.json     metadata: {name, scope: [...], started_at, operator, notes_path}
    findings.jsonl      append-only structured findings (one JSON per line)
    creds.jsonl         credential cache (mode 0600)
    loot/               extracted blobs (dumped data, ticket files)
    screenshots/        PNG output (reserved for a future screenshot tool)
    notes.md            operator free-form notes

Active engagement resolution order:
  1. ``KALIMCP_ENGAGEMENT`` env var (operator/CI override).
  2. State file at ``~/.kalimcp/active_engagement`` (set by
     ``engagement_use``).
  3. ``_default`` (auto-created the first time anything writes).

All filesystem operations are best-effort: a write failure
returns ``False`` rather than raising — workspace persistence must
never break the tool path. The audit log remains the
ground-truth forensic record.
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import os
import re
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT_DIR = Path.home() / ".kalimcp"
ENGAGEMENTS_DIR = ROOT_DIR / "engagements"
ACTIVE_STATE_FILE = ROOT_DIR / "active_engagement"
DEFAULT_ENGAGEMENT = "_default"

# Common wordlist paths the agent might want to query.
_WORDLIST_DIRS = [
    "/usr/share/wordlists",
    "/usr/share/seclists",
]


# ---------- engagement resolution ----------

def _root() -> Path:
    return ENGAGEMENTS_DIR


def current_engagement() -> str:
    """Return the active engagement name."""
    env_name = os.environ.get("KALIMCP_ENGAGEMENT")
    if env_name:
        return env_name
    try:
        if ACTIVE_STATE_FILE.exists():
            value = ACTIVE_STATE_FILE.read_text(encoding="utf-8").strip()
            if value:
                return value
    except OSError:
        pass
    return DEFAULT_ENGAGEMENT


def engagement_dir(name: str | None = None) -> Path:
    """Return the directory for ``name`` (or the active engagement). Creates it."""
    n = name or current_engagement()
    p = _root() / _sanitize_name(n)
    try:
        p.mkdir(parents=True, exist_ok=True)
        (p / "loot").mkdir(exist_ok=True)
        (p / "screenshots").mkdir(exist_ok=True)
    except OSError:
        pass
    return p


def _sanitize_name(name: str) -> str:
    """Restrict engagement names to a safe filename charset."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    # The charset allows '.', so '..' (and '.') survive the regex unchanged
    # and would resolve *outside* the engagements root — single-segment path
    # traversal. A name that is nothing but dots is a traversal token, not a
    # name; collapse it (and the empty case) to the default.
    if not safe or set(safe) <= {"."}:
        return DEFAULT_ENGAGEMENT
    return safe


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


# ---------- engagement lifecycle ----------

def create(name: str, scope: list[str] | None = None, operator: str = "") -> dict[str, Any]:
    """Bootstrap a new engagement directory + metadata file."""
    safe = _sanitize_name(name)
    p = _root() / safe
    if p.exists() and (p / "engagement.json").exists():
        return {"ok": False, "error": "exists", "name": safe, "path": str(p)}
    try:
        p.mkdir(parents=True, exist_ok=True)
        (p / "loot").mkdir(exist_ok=True)
        (p / "screenshots").mkdir(exist_ok=True)
        meta = {
            "name": safe,
            "scope": list(scope or []),
            "started_at": _now(),
            "operator": operator,
            "notes_path": str(p / "notes.md"),
        }
        (p / "engagement.json").write_text(
            json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8",
        )
        # Touch notes.md so operators see it exists.
        (p / "notes.md").touch()
        return {"ok": True, "name": safe, "path": str(p), "meta": meta}
    except OSError as exc:
        return {"ok": False, "error": "write_failed", "message": str(exc)}


def list_all() -> list[dict[str, Any]]:
    """Enumerate engagements present on disk (sorted by start time desc)."""
    out: list[dict[str, Any]] = []
    if not _root().exists():
        return out
    for child in _root().iterdir():
        if not child.is_dir():
            continue
        meta_path = child / "engagement.json"
        if not meta_path.exists():
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        out.append({
            "name": meta.get("name", child.name),
            "started_at": meta.get("started_at", ""),
            "scope": meta.get("scope", []),
            "path": str(child),
        })
    out.sort(key=lambda e: e["started_at"], reverse=True)
    return out


def use(name: str) -> dict[str, Any]:
    """Set the active engagement (writes the state file)."""
    safe = _sanitize_name(name)
    target = _root() / safe
    if not target.exists() or not (target / "engagement.json").exists():
        return {"ok": False, "error": "not_found", "name": safe}
    try:
        ROOT_DIR.mkdir(parents=True, exist_ok=True)
        ACTIVE_STATE_FILE.write_text(safe, encoding="utf-8")
        return {"ok": True, "name": safe}
    except OSError as exc:
        return {"ok": False, "error": "write_failed", "message": str(exc)}


def status(name: str | None = None) -> dict[str, Any]:
    """Return metadata + counts for the named (or active) engagement."""
    n = name or current_engagement()
    p = engagement_dir(n)
    meta_path = p / "engagement.json"
    meta: dict[str, Any] = {}
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            meta = {}
    findings_count = _count_lines(p / "findings.jsonl")
    creds_count = _count_lines(p / "creds.jsonl")
    loot_count = 0
    loot_dir = p / "loot"
    if loot_dir.exists():
        loot_count = sum(
            1 for f in loot_dir.iterdir() if f.is_file() and f.name != _LOOT_MANIFEST
        )
    return {
        "name": meta.get("name", _sanitize_name(n)),
        "scope": meta.get("scope", []),
        "started_at": meta.get("started_at", ""),
        "operator": meta.get("operator", ""),
        "path": str(p),
        "findings_count": findings_count,
        "creds_count": creds_count,
        "loot_count": loot_count,
        "is_active": n == current_engagement(),
    }


def _count_lines(p: Path) -> int:
    try:
        if not p.exists():
            return 0
        with p.open("rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


# ---------- findings ----------

# Payload keys that count as supporting evidence for a finding. A finding
# carrying any of these (or recorded by a tool, i.e. with a source_tool) is
# considered backed by proof; one with none is a bare claim.
_EVIDENCE_KEYS: tuple[str, ...] = (
    "evidence", "proof", "loot", "loot_ref", "output", "raw",
    "request", "response", "screenshot", "url", "ports", "banner",
)


def evidence_advisory(
    payload: dict[str, Any] | None, source_tool: str = ""
) -> str | None:
    """Advisory (never blocking) check that a finding is backed by evidence.

    Returns a nudge string when a finding has neither a ``source_tool`` nor
    any recognized evidence field in its payload — i.e. it's a bare claim
    with nothing to back it in a report — else ``None``. Per the
    no-authorization-gate design rule this never prevents the record; the
    caller surfaces the message alongside a successful write so the agent
    is nudged to attach the tool output or a loot reference.
    """
    if source_tool and source_tool.strip():
        return None
    if isinstance(payload, dict):
        for k in _EVIDENCE_KEYS:
            value = payload.get(k)
            if value not in (None, "", [], {}, ()):
                return None
    return (
        "finding recorded without evidence: no source_tool and no "
        "evidence/proof/loot/output field in the payload. Attach the tool "
        "output or a loot reference so the finding is defensible in a report. "
        "(advisory only — the finding was still recorded.)"
    )


def record_finding(
    category: str,
    host: str,
    payload: dict[str, Any] | None = None,
    *,
    name: str | None = None,
    source_tool: str = "",
) -> bool:
    """Append a finding to ``findings.jsonl``. Returns False on write failure."""
    p = engagement_dir(name) / "findings.jsonl"
    entry = {
        "ts": _now(),
        "category": category,
        "host": host,
        "source_tool": source_tool,
        "payload": payload or {},
    }
    return _append_jsonl(p, entry)


def query_findings(
    *,
    category: str | None = None,
    host: str | None = None,
    since: str | None = None,
    name: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Read findings.jsonl, optionally filtered. Most recent first."""
    p = engagement_dir(name) / "findings.jsonl"
    rows = _read_jsonl(p)
    if category is not None:
        rows = [r for r in rows if r.get("category") == category]
    if host is not None:
        rows = [r for r in rows if r.get("host") == host]
    if since is not None:
        rows = [r for r in rows if r.get("ts", "") >= since]
    rows.sort(key=lambda r: r.get("ts", ""), reverse=True)
    return rows[: max(1, int(limit))]


def list_hosts(*, name: str | None = None) -> list[str]:
    """Derive a unique sorted host list from findings + creds."""
    hosts: set[str] = set()
    for row in _read_jsonl(engagement_dir(name) / "findings.jsonl"):
        h = row.get("host")
        if h:
            hosts.add(str(h))
    for row in _read_jsonl(engagement_dir(name) / "creds.jsonl"):
        h = row.get("host")
        if h:
            hosts.add(str(h))
    return sorted(hosts)


# ---------- credentials ----------

def record_cred(
    host: str,
    proto: str,
    user: str,
    secret: str,
    *,
    source_tool: str = "",
    name: str | None = None,
) -> bool:
    """Append a credential to ``creds.jsonl`` (mode 0600).

    ``secret`` is stored verbatim — the engagement directory is the
    operator's loot cache, not the audit log. The directory should
    live on encrypted storage if the operator needs at-rest secrecy.
    """
    p = engagement_dir(name) / "creds.jsonl"
    entry = {
        "ts": _now(),
        "host": host,
        "proto": proto,
        "user": user,
        "secret": secret,
        "source_tool": source_tool,
    }
    ok = _append_jsonl(p, entry)
    if ok:
        try:
            p.chmod(0o600)
        except OSError:
            pass
    return ok


def query_creds(
    *,
    host: str | None = None,
    user: str | None = None,
    proto: str | None = None,
    name: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    p = engagement_dir(name) / "creds.jsonl"
    rows = _read_jsonl(p)
    if host is not None:
        rows = [r for r in rows if r.get("host") == host]
    if user is not None:
        rows = [r for r in rows if r.get("user") == user]
    if proto is not None:
        rows = [r for r in rows if r.get("proto") == proto]
    rows.sort(key=lambda r: r.get("ts", ""), reverse=True)
    return rows[: max(1, int(limit))]


# ---------- loot ----------
#
# The loot store is the operator's evidence cache. Each blob is written
# owner-only (0600) and its SHA-256 is recorded in a per-engagement
# manifest (``loot/.manifest.json``, also 0600). That lets an operator
# transfer a blob off the box and verify it arrived intact, and lets
# ``verify_loot`` detect on-disk tampering or corruption against the hash
# recorded at write time (#20).

_LOOT_MANIFEST = ".manifest.json"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _loot_manifest_path(name: str | None = None) -> Path:
    return engagement_dir(name) / "loot" / _LOOT_MANIFEST


def _read_loot_manifest(name: str | None = None) -> dict[str, Any]:
    p = _loot_manifest_path(name)
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_loot_manifest(manifest: dict[str, Any], name: str | None = None) -> None:
    p = _loot_manifest_path(name)
    try:
        p.write_text(json.dumps(manifest, sort_keys=True, indent=2), encoding="utf-8")
        p.chmod(0o600)
    except OSError:
        pass


def write_loot(blob_name: str, data: bytes | str, *, name: str | None = None) -> dict[str, Any]:
    """Write ``data`` into ``loot/<safe_name>`` (mode 0600).

    Records the blob's SHA-256 + size in the loot manifest and returns
    them, so the operator can checksum-verify a later transfer.
    """
    safe = _sanitize_name(blob_name)
    p = engagement_dir(name) / "loot" / safe
    raw = data.encode("utf-8") if isinstance(data, str) else data
    try:
        p.write_bytes(raw)
        p.chmod(0o600)
        size = p.stat().st_size
    except OSError as exc:
        return {"ok": False, "error": "write_failed", "message": str(exc)}
    digest = _sha256_bytes(raw)
    manifest = _read_loot_manifest(name)
    manifest[safe] = {"sha256": digest, "size_bytes": size, "written_at": _now()}
    _write_loot_manifest(manifest, name)
    return {"ok": True, "path": str(p), "size_bytes": size, "sha256": digest}


def list_loot(*, name: str | None = None) -> list[dict[str, Any]]:
    p = engagement_dir(name) / "loot"
    out: list[dict[str, Any]] = []
    if not p.exists():
        return out
    manifest = _read_loot_manifest(name)
    for child in sorted(p.iterdir()):
        if not child.is_file() or child.name == _LOOT_MANIFEST:
            continue
        try:
            stat = child.stat()
        except OSError:
            continue
        entry: dict[str, Any] = {
            "name": child.name,
            "path": str(child),
            "size_bytes": stat.st_size,
            "mtime": datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat(timespec="seconds"),
        }
        recorded = manifest.get(child.name)
        if isinstance(recorded, dict) and recorded.get("sha256"):
            entry["sha256"] = recorded["sha256"]
        out.append(entry)
    return out


def read_loot(blob_name: str, *, name: str | None = None) -> dict[str, Any]:
    """Read a loot blob. Returns text or base64-encoded bytes.

    Includes the blob's current ``sha256`` and a ``verified`` flag (does it
    still match the hash recorded when it was written?).
    """
    import base64
    safe = _sanitize_name(blob_name)
    p = engagement_dir(name) / "loot" / safe
    if not p.exists():
        return {"ok": False, "error": "not_found"}
    try:
        data = p.read_bytes()
    except OSError as exc:
        return {"ok": False, "error": "read_failed", "message": str(exc)}
    digest = _sha256_bytes(data)
    recorded = _read_loot_manifest(name).get(safe)
    recorded_hash = recorded.get("sha256") if isinstance(recorded, dict) else None
    common: dict[str, Any] = {
        "ok": True,
        "size_bytes": len(data),
        "sha256": digest,
        "verified": (recorded_hash == digest) if recorded_hash else None,
    }
    # Detect whether the blob is plausibly text.
    try:
        text = data.decode("utf-8")
        return {**common, "encoding": "utf-8", "text": text}
    except UnicodeDecodeError:
        return {
            **common,
            "encoding": "base64",
            "base64": base64.b64encode(data).decode("ascii"),
        }


def verify_loot(
    blob_name: str, expected_sha256: str = "", *, name: str | None = None
) -> dict[str, Any]:
    """Checksum-verify a loot blob.

    Recomputes the blob's SHA-256 and compares it to ``expected_sha256``
    when given, otherwise to the hash recorded in the manifest at write
    time. ``verified`` is true only when the comparison hash exists and
    matches — a tampered or truncated blob, or one with no reference hash,
    is never silently reported as verified.
    """
    safe = _sanitize_name(blob_name)
    p = engagement_dir(name) / "loot" / safe
    if not p.exists():
        return {"ok": False, "error": "not_found"}
    try:
        digest = _sha256_bytes(p.read_bytes())
    except OSError as exc:
        return {"ok": False, "error": "read_failed", "message": str(exc)}
    recorded = _read_loot_manifest(name).get(safe)
    recorded_hash = recorded.get("sha256") if isinstance(recorded, dict) else None
    reference = expected_sha256.strip().lower() or recorded_hash
    return {
        "ok": True,
        "sha256": digest,
        "recorded_sha256": recorded_hash,
        "compared_against": "expected" if expected_sha256.strip() else "manifest",
        "verified": bool(reference) and reference == digest,
    }


# ---------- notes ----------

def note_append(text: str, *, name: str | None = None) -> bool:
    """Append a timestamped block to notes.md."""
    p = engagement_dir(name) / "notes.md"
    block = f"\n## {_now()}\n\n{text}\n"
    try:
        with p.open("a", encoding="utf-8") as fh:
            fh.write(block)
        return True
    except OSError:
        return False


# ---------- wordlists ----------

def list_wordlists() -> list[dict[str, Any]]:
    """Enumerate wordlists under /usr/share/wordlists + seclists."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for root in _WORDLIST_DIRS:
        root_p = Path(root)
        if not root_p.exists():
            continue
        for child in root_p.rglob("*"):
            if not child.is_file():
                continue
            # Skip very large files (.bz2 archives, etc.) to keep
            # the list scannable.
            try:
                size = child.stat().st_size
            except OSError:
                continue
            key = str(child)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "path": key,
                "size_bytes": size,
                "name": child.name,
            })
    out.sort(key=lambda e: e["path"])
    return out


# ---------- scope matching ----------

def scope_matches(target: str) -> bool:
    """True iff ``target`` matches any pattern in the active engagement's scope.

    Empty scope (or no engagement) returns True — operator hasn't
    declared a scope, so we don't gate.
    """
    meta_path = engagement_dir() / "engagement.json"
    if not meta_path.exists():
        return True
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return True
    patterns = meta.get("scope") or []
    if not patterns:
        return True
    return any(_pattern_matches(target, p) for p in patterns)


def _pattern_matches(target: str, pattern: str) -> bool:
    """Match a single scope pattern. CIDR, URL, or domain glob."""
    host = _extract_host(target)
    if not host:
        return False
    # CIDR?
    try:
        network = ipaddress.ip_network(pattern, strict=False)
        try:
            return ipaddress.ip_address(host) in network
        except ValueError:
            return False
    except ValueError:
        pass
    if "://" in pattern:
        pat_host = urllib.parse.urlparse(pattern).hostname or pattern
    else:
        pat_host = pattern
    return fnmatch.fnmatchcase(host.lower(), pat_host.lower())


def _extract_host(target: str) -> str:
    if not target:
        return ""
    if "://" in target:
        try:
            return urllib.parse.urlparse(target).hostname or ""
        except ValueError:
            return ""
    # Bracketed IPv6, with or without a port: [::1] / [2001:db8::1]:8080.
    # Without this the multi-colon literal falls through to the bare return
    # below and `ip_address()` later chokes on the brackets+port, so the
    # scope warning silently never fires for IPv6 targets.
    if target.startswith("["):
        end = target.find("]")
        if end != -1:
            return target[1:end]
    # Strip a trailing path (host/rest), but not an absolute filesystem path.
    if "/" in target and not target.startswith("/"):
        target = target.split("/", 1)[0]
    # host:port — only strip when there's exactly one colon, so a bare
    # (unbracketed) IPv6 literal like ::1 is left intact for ip_address().
    if target.count(":") == 1:
        return target.split(":", 1)[0]
    return target


# ---------- JSONL helpers ----------

def _append_jsonl(path: Path, entry: dict[str, Any]) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
        return True
    except (OSError, TypeError, ValueError):
        return False


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    return rows
