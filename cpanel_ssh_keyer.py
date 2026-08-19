#!/usr/bin/env python3
"""
cpanel-ssh-keyer — authorize ONE SSH key on N cPanel accounts automatically.

Why this exists:
cPanel hosts say "SSH keys need to be enabled per cPanel account" — and they're
right, but that's a 2-minute GUI click per site. If you run a reseller with 20
accounts, that's 40 minutes of clicking. This tool does it via the cPanel UAPI
on port 2083 instead: import the key + authorize it, then VERIFY with a real SSH
login. No GUI, no per-account clicking.

Auth methods (in order of preference):
1. cPanel API token  (cPanel → Security → Manage API Tokens → Create)
2. cPanel username + password (Basic auth over HTTPS 2083)

Usage:
    python3 cpanel_ssh_keyer.py --key ~/.ssh/lion_wildfarm.pub
    python3 cpanel_ssh_keyer.py --key ~/.ssh/lion_wildfarm.pub --sites sites.json
    python3 cpanel_ssh_keyer.py --key ... --sites sites.json --verify-only
    python3 cpanel_ssh_keyer.py --key ... --dry-run

Config (sites.json) — one entry per account:
[
  {
    "host": "rs19.cphost.co.za",
    "domain": "knysnaparadise.com",
    "user": "wwwknysnaparadis",
    "token": "32-char-cpanel-api-token",   // OR:
    "password": "cpanel-password",
    "port": 2083
  }
]

Envvars override per-site fields: CPANEL_TOKEN, CPANEL_PASSWORD, CPANEL_PORT.

Output: PASS/FAIL per account, and a final summary. FAIL includes the reason
(token invalid, key already exists, shell not enabled, SSH still rejected).

Safety:
- Reads the public key file ONLY (never the private key).
- No destructive actions: import + authorize are additive; --verify-only only SSH-tests.
- Never prints tokens/passwords; redacts them in errors.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def redact(s: str) -> str:
    """Redact any 32-char token or obvious secret-looking string."""
    import re
    return re.sub(r"[A-Za-z0-9]{32,}", "[REDACTED]", s or "")


def load_sites(path: str | None) -> list[dict]:
    if not path:
        # default: try sites.json in same dir
        p = Path(__file__).parent / "sites.json"
        if not p.exists():
            print("No sites.json found. Use --sites or create one (see README).", file=sys.stderr)
            sys.exit(2)
        path = str(p)
    data = json.loads(Path(path).read_text())
    if not isinstance(data, list):
        print("sites.json must be a JSON list of account objects.", file=sys.stderr)
        sys.exit(2)
    # env overrides
    for s in data:
        if os.environ.get("CPANEL_TOKEN"):
            s["token"] = os.environ["CPANEL_TOKEN"]
        if os.environ.get("CPANEL_PASSWORD"):
            s["password"] = os.environ["CPANEL_PASSWORD"]
        if os.environ.get("CPANEL_PORT"):
            s["port"] = int(os.environ["CPANEL_PORT"])
        s.setdefault("port", 2083)
    return data


def import_key(site: dict, pubkey: str, key_name: str) -> dict:
    """SSH::importkey (API2) — imports the key. Params: key (content), name."""
    return api2_call(site, "importkey", {"key": pubkey, "name": key_name})


def authorize_key(site: dict, key_name: str) -> dict:
    """SSH::authkey (API2) — authorize the key. Params: key (name), action."""
    return api2_call(site, "authkey", {"key": key_name, "action": "authorize"})


def list_keys(site: dict) -> dict:
    """SSH::listkeys (API2) — list keys."""
    return api2_call(site, "listkeys", {})


def api2_call(site: dict, func: str, params: dict) -> dict:
    """Call the cPanel API2 JSON endpoint (json-api/cpanel) for module SSH.
    API2 param names (name, action) differ from UAPI — learned live 2026-08-19."""
    import urllib.parse
    host = site["host"]
    port = site.get("port", 2083)
    user = site["user"]
    url = f"https://{host}:{port}/json-api/cpanel"
    q = {
        "cpanel_jsonapi_module": "SSH",
        "cpanel_jsonapi_func": func,
        "cpanel_jsonapi_apiversion": 2,
    }
    q.update(params)
    body = urllib.parse.urlencode(q).encode()
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if site.get("token"):
        headers["Authorization"] = f"cpanel {user}:{site['token']}"
    elif site.get("password"):
        basic = base64.b64encode(f"{user}:{site['password']}".encode()).decode()
        headers["Authorization"] = f"Basic {basic}"
    else:
        raise RuntimeError(f"{site['domain']}: no token or password configured")
    req = urllib.request.Request(url, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body_txt = e.read().decode(errors="replace")
        raise RuntimeError(f"{site['domain']}: HTTP {e.code} — {redact(body_txt[:300])}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"{site['domain']}: {e.reason}")


def api_call(site: dict, endpoint: str, params: dict) -> dict:
    """Legacy UAPI caller kept for reference — this host's SSH module is API2-only."""
    return api2_call(site, endpoint.split("/")[-1], params)


def ssh_ok(site: dict, key_path: str, port: int = 22000, timeout: int = 12) -> tuple[bool, str]:
    """Real SSH test: `ssh -i KEY -p PORT user@domain 'echo OK'`.
    key_path may point to the .pub (for reading) — SSH needs the PRIVATE key,
    so strip a trailing .pub for the identity file (live bug 2026-08-19)."""
    identity = str(key_path)
    if identity.endswith(".pub"):
        identity = identity[:-4]
    cmd = [
        "ssh", "-i", identity, "-p", str(port),
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=8",
        f"{site['user']}@{site['domain']}",
        "echo OK",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout + r.stderr)
        if "OK" in out.splitlines() and r.returncode == 0:
            return True, "SSH login OK"
        if "Permission denied" in out:
            return False, "key still rejected (Permission denied)"
        if "Shell access is not enabled" in out:
            return False, "key accepted but SHELL ACCESS DISABLED"
        return False, f"ssh rc={r.returncode}: {redact(out.strip()[-120:])}"
    except subprocess.TimeoutExpired:
        return False, "ssh timeout"


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Authorize one SSH key on N cPanel accounts.")
    ap.add_argument("--key", required=True, help="Path to the PUBLIC key file (.pub)")
    ap.add_argument("--sites", default=None, help="Path to sites.json")
    ap.add_argument("--key-name", default=None, help="Key name in cPanel (default: stem of --key)")
    ap.add_argument("--ssh-port", type=int, default=22000, help="SSH port for verify (default 22000)")
    ap.add_argument("--dry-run", action="store_true", help="Show config + what would be done, no API calls")
    ap.add_argument("--verify-only", action="store_true", help="Only SSH-test each account (no API calls)")
    ap.add_argument("--sleep", type=float, default=1.0, help="Seconds between accounts (anti-rate-limit)")
    args = ap.parse_args()

    key_path = Path(args.key).expanduser()
    if not key_path.exists():
        print(f"Public key not found: {key_path}", file=sys.stderr)
        return 2
    pubkey = key_path.read_text().strip()
    key_name = args.key_name or key_path.stem

    sites = load_sites(args.sites)
    if not sites:
        print("No accounts to process.", file=sys.stderr)
        return 2

    print(f"🔑 Key: {key_path} (name: {key_name})")
    print(f"🌐 Accounts: {len(sites)}")
    print()

    if args.dry_run:
        for s in sites:
            auth = "token" if s.get("token") else ("password" if s.get("password") else "❌ NONE")
            print(f"  [dry] {s['domain']:<32} user={s['user']:<20} auth={auth}")
        print("\nDry run only — no API calls made.")
        return 0

    results = []
    for s in sites:
        domain = s["domain"]
        print(f"── {domain} ({s['user']}) ──", flush=True)

        if args.verify_only:
            ok, msg = ssh_ok(s, key_path, args.ssh_port)
            results.append((domain, ok, msg))
            print(f"   {'✅' if ok else '❌'} {msg}")
            time.sleep(args.sleep)
            continue

        # 1. import (cPanel may store under its own name — use the RETURNED name)
        try:
            imp = import_key(s, pubkey, key_name)
        except Exception as e:
            results.append((domain, False, str(e)))
            print(f"   ❌ import failed: {redact(str(e)[:150])}")
            time.sleep(args.sleep)
            continue
        imp_res = imp.get("cpanelresult", imp)
        if imp_res.get("error"):
            err_msg = str(imp_res["error"])
            # Key already imported in a previous run → NOT a failure; skip to
            # authorize (live 2026-08-19: re-runs on 14 accounts hit this and
            # the tool wrongly reported them as FAILED before authorizing).
            if "already exists" in err_msg.lower():
                print(f"   ↪ key already present — skipping to authorize")
            else:
                results.append((domain, False, f"import: {redact(err_msg[:150])}"))
                print(f"   ❌ import: {redact(err_msg[:150])}")
                time.sleep(args.sleep)
                continue
        # the stored key name may differ from the requested one (live 2026-08-19:
        # requested 'lion_wildfarm' but cPanel returned 'id_dsa.pub')
        stored_name = None
        try:
            d = imp_res.get("data") or []
            if isinstance(d, list) and d and isinstance(d[0], dict):
                stored_name = d[0].get("name")
        except Exception:
            pass
        if stored_name:
            print(f"   ✓ key stored as '{stored_name}'")
            auth_name = stored_name
        else:
            auth_name = key_name

        # 2. authorize (ignore failure if key already authorized)
        try:
            auth = authorize_key(s, auth_name)
        except Exception as e:
            print(f"   ⚠ authorize step: {redact(str(e)[:120])}")

        # 3. verify with a real SSH login
        ok, msg = ssh_ok(s, key_path, args.ssh_port)
        results.append((domain, ok, msg))
        print(f"   {'✅' if ok else '❌'} {msg}")
        time.sleep(args.sleep)

    print()
    print("=== SUMMARY ===")
    passed = sum(1 for _, ok, _ in results if ok)
    for domain, ok, msg in results:
        print(f"  {'✅' if ok else '❌'} {domain:<32} {msg}")
    print(f"\n{passed}/{len(results)} accounts working")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
