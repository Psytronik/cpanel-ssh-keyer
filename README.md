# cpanel-ssh-keyer 🔑

**Authorize one SSH key on N cPanel accounts — automatically.**

cPanel hosts will tell you *"SSH keys need to be enabled per cPanel account."*
They're right — but when you run a reseller with 20+ accounts, that means 2
minutes of GUI clicking per site. This tool does it via the **cPanel UAPI**
(port 2083) instead: import the key, authorize it, then **verify with a real
SSH login** so you know it actually works.

## Why

You have 20 cPanel accounts, one SSH key, and no desire to click "Import →
Authorize → test" twenty times. You also don't want to trust a support agent
to do it right. This is the 2-minute script that does the 40-minute job —
and proves each account works.

## Requirements

- Python 3.9+
- `ssh` client on PATH (for verification)
- Per-account cPanel **API token** (preferred) or cPanel **username + password**

## Quick start

```bash
# 1. Create sites.json from the template
cp sites.example.json sites.json
#    → fill in your accounts (host, domain, user, token)

# 2. Dry run (shows what would happen, no API calls)
python3 cpanel_ssh_keyer.py --key ~/.ssh/lion_wildfarm.pub --dry-run

# 3. Run it for real
python3 cpanel_ssh_keyer.py --key ~/.ssh/lion_wildfarm.pub

# 4. Just re-test SSH (no API calls)
python3 cpanel_ssh_keyer.py --key ~/.ssh/lion_wildfarm.pub --verify-only
```

## Config

`sites.json` — a JSON list, one object per account:

```json
[
  {
    "host": "rs19.cphost.co.za",
    "domain": "knysnaparadise.com",
    "user": "wwwknysnaparadis",
    "token": "YOUR-32-CHAR-CPANEL-API-TOKEN",
    "port": 2083
  },
  {
    "host": "rs19.cphost.co.za",
    "domain": "anothersite.com",
    "user": "anotheruser",
    "password": "cpanel-password"
  }
]
```

Either `token` **or** `password` per account. Env overrides:
`CPANEL_TOKEN`, `CPANEL_PASSWORD`, `CPANEL_PORT`.

**Getting an API token:** cPanel → Security → **Manage API Tokens** → Create →
name it (e.g. `ssh-keyer`) → copy the 32-char token. Revoke anytime.

## What it does per account

1. `SSH/import_key` — imports your public key (`--key` must be the `.pub` file)
2. `SSH/authorize_key` — authorizes it for that account
3. Real SSH test on port 22000 — `ssh -i <key> -p 22000 user@domain 'echo OK'`

Output is one line per account with ✅/❌ and a final summary.

## Safety

- **Reads the public key only** — never the private key.
- **Additive only** — import + authorize never remove or overwrite existing keys.
- **Never prints tokens/passwords** — redacted in all output and errors.
- `--dry-run` and `--verify-only` make zero API calls.

## Why port 22000?

Many cPanel/WHM reseller hosts (e.g. CPHost's `rsNN.cphost.co.za`) move SSH to
port 22000; port 22 is firewalled. If your host uses 22, pass `--ssh-port 22`
or set it in the site config.

## License

MIT — use it, fork it, ship it. If it saves you an afternoon, that's the point.
