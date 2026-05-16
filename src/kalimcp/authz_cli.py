# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Aaron K. Clark
"""`kalimcp-authz` CLI — manage authorization tokens + scopes.

Subcommands:
  add     — generate a new authorization (random UUID token) with scope.
  list    — show all known tokens (id + name + scope + expiry; token shown ONCE on add only).
  remove  — delete an authorization by name or token id.
  check   — sanity-test: would token X cover target Y?

Tokens are stored at ~/.kalimcp/authorizations.json (mode 0600).
"""

from __future__ import annotations

import argparse
import secrets
import sys
from datetime import datetime, timezone

from . import authz


def cmd_add(args: argparse.Namespace) -> int:
    existing = authz.load_authorizations()
    if any(a.name == args.name for a in existing):
        print(f"error: an authorization named {args.name!r} already exists", file=sys.stderr)
        return 1
    if not args.scope:
        print("error: --scope is required (one or more times)", file=sys.stderr)
        return 1

    token = args.token or secrets.token_urlsafe(32)
    a = authz.Authorization(
        name=args.name,
        token=token,
        scope=tuple(args.scope),
        expires=args.expires,
        explicit_unsafe=bool(args.explicit_unsafe),
    )
    existing.append(a)
    authz.save_authorizations(existing)
    print("added.")
    print(f"  name:    {a.name}")
    print(f"  id:      {a.token_id()}")
    print(f"  scope:   {list(a.scope)}")
    print(f"  expires: {a.expires or '(never)'}")
    if a.explicit_unsafe:
        print(f"  explicit_unsafe: True")
    print()
    print("Token (write this down — won't be shown again):")
    print(f"  {a.token}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    existing = authz.load_authorizations()
    if not existing:
        print("(no authorizations configured)")
        return 0
    now = datetime.now(timezone.utc)
    for a in existing:
        status = "EXPIRED" if a.is_expired(now=now) else "active"
        unsafe = " UNSAFE" if a.explicit_unsafe else ""
        print(f"  {a.token_id()}  {status}{unsafe}  {a.name}")
        for s in a.scope:
            print(f"    scope: {s}")
        if a.expires:
            print(f"    expires: {a.expires}")
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    existing = authz.load_authorizations()
    before = len(existing)
    existing = [
        a for a in existing
        if a.name != args.identifier and a.token_id() != args.identifier
    ]
    if len(existing) == before:
        print(f"error: no authorization with name or id {args.identifier!r}", file=sys.stderr)
        return 1
    authz.save_authorizations(existing)
    print(f"removed {before - len(existing)} authorization(s).")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    try:
        auth = authz.check(target=args.target, token=args.token)
    except authz.AuthzError as exc:
        print(f"DENIED: {exc}", file=sys.stderr)
        return 1
    print(f"OK: target {args.target} is in scope for authorization {auth.name!r} (id {auth.token_id()})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kalimcp-authz",
        description="Manage authorization tokens for KaliMCP active-scan tools.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="Create a new authorization.")
    a.add_argument("--name", required=True, help="Human label for the authorization (e.g. 'Q3 pentest engagement').")
    a.add_argument("--scope", action="append", required=True,
                   help="Allowed target pattern. Pass multiple times. CIDRs ('10.0.0.0/24'), "
                        "domain globs ('*.example.com'), or URLs.")
    a.add_argument("--expires", help="ISO 8601 expiry (e.g. 2026-08-01T00:00:00Z). Omit for no expiry.")
    a.add_argument("--token", help="Specific token value. Omit to generate a random one.")
    a.add_argument("--explicit-unsafe", action="store_true",
                   help="Allow targets normally on the refuse list (.gov, .mil, financial). "
                        "Requires KALIMCP_ALLOW_REFUSED=1 at runtime too.")
    a.set_defaults(func=cmd_add)

    l = sub.add_parser("list", help="List all configured authorizations.")
    l.set_defaults(func=cmd_list)

    r = sub.add_parser("remove", help="Remove an authorization by name or token id.")
    r.add_argument("identifier", help="Authorization name OR 8-char token id.")
    r.set_defaults(func=cmd_remove)

    c = sub.add_parser("check", help="Test whether a token would cover a target.")
    c.add_argument("--token", required=True)
    c.add_argument("--target", required=True)
    c.set_defaults(func=cmd_check)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
