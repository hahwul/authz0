<h1 align="center">authz0 v2</h1>

<p align="center">
  <b>Automated authorization (access-control) testing — session-based, incremental, AI-friendly.</b><br>
  A Crystal rewrite of <a href="https://github.com/hahwul/authz0">authz0</a>.
</p>

```
  __ _ _   _ ___| |_ ____  / _ \
 / _` | | | |_  / __|_  / | | | |
| (_| | |_| |/ /| |_ / /| | |_| |
 \__,_|\__,_/___|\__/___|\___/
```

authz0 identifies unauthorized access (broken access control / IDOR-style
authorization flaws) by probing the **same URLs with different roles &
credentials** and comparing the observed access against the policy you declare.

Where v1 made you hand-write one big YAML template, **v2 builds a test session
incrementally** with small commands (`session new`, `url add`, `cred add`,
`scan`) — a flow that's pleasant for humans and trivial for an AI agent to
drive command-by-command.

## Highlights

- **Session-based workflow** — `~/.authz0/sessions/<name>/` holds plain JSON you
  can read, diff, and version (minus secrets).
- **Incremental** — add URLs, roles, and rules a few at a time; no all-or-nothing template.
- **Imports** — OpenAPI/Swagger, HAR (ZAP/Chrome/Burp), Burp XML, Postman, plain URL lists.
- **Rich reports** — table, plain (grep-friendly), JSON, Markdown, CSV, **SARIF** (CI/code-scanning), and self-contained **HTML**.
- **Concurrent scanner** with proxy support (route through Burp/ZAP via `--proxy`).
- **Security-aware** — `creds.json` is `chmod 600`, secrets are masked in output, `.gitignore` is auto-created, and `doctor` audits it all.
- **v1-compatible** — `export yaml` writes a template the original Go tool can consume.

## Installation

```bash
# Homebrew (macOS / Linux)
brew install hahwul/authz0/authz0

# Arch (AUR)
yay -S authz0

# Snap
sudo snap install authz0

# Docker
docker run --rm ghcr.io/hahwul/authz0:latest --help

# Prebuilt binary (Linux static musl / macOS) — from GitHub Releases
#   https://github.com/hahwul/authz0/releases

# From source (requires Crystal >= 1.19)
git clone https://github.com/hahwul/authz0
cd authz0
shards build --release        # zero runtime deps; binary at ./bin/authz0
./bin/authz0 --help
```

`.deb`, `.rpm`, `.apk` packages and a CycloneDX SBOM are attached to each release.

## Quickstart

```bash
# 1. create a session against a target
authz0 session new shop --base-url https://shop.example.com

# 2. declare endpoints and their policy
authz0 url add shop /account                       # public
authz0 url add shop /admin       --allow-role admin   --alias "admin panel"
authz0 url add shop /orders/1234 --deny-role  guest
authz0 url add shop /login --method POST --content-type json --body '{"u":"x"}'

# 3. add the identities to test with (secrets stay out of shell history)
export ADMIN_JWT=...   USER_JWT=...
authz0 cred add shop admin --header 'Authorization: Bearer ${ADMIN_JWT}'
authz0 cred add shop user  --header 'Authorization: Bearer ${USER_JWT}'

# 4. tell authz0 what "access granted" looks like (optional; defaults to 2xx)
authz0 assert add shop --success-status 200,201 --fail-status 403

# 5. scan
authz0 scan shop                       # live table
authz0 scan shop --output sarif --save report.sarif --fail-on-findings
```

A finding (`X`) means **observed access didn't match declared policy** — e.g. a
`user` token reached an `admin`-only endpoint, or anonymous access succeeded on
a protected one.

## Importing

```bash
authz0 import openapi shop ./openapi.yaml     # JSON or YAML
authz0 import har     shop ./traffic.har      # ZAP / Chrome / Burp HAR
authz0 import burp    shop ./items.xml        # Burp "Save items" XML
authz0 import postman shop ./collection.json  # Postman v2.x
authz0 import urls    shop ./urls.txt         # one per line, "METHOD url" ok
```
Re-imports are idempotent: endpoints already present (same method+path+body) are skipped.

## Commands

| Command | Purpose |
|---|---|
| `session new/list/show/set/delete/rename/clone` | Manage test projects |
| `url add/list/show/update/remove` | Manage endpoints + allow/deny-role policy |
| `cred add/list/update/remove` | Manage credentials (roles); values masked by default |
| `assert add/list/remove` | Access-detection rules (success-status / fail-status / fail-regex / fail-size) |
| `scan <session>` | Run the scan and report findings |
| `results list/show/clean <session>` | Browse archived scans |
| `stats` | Cross-session overview + open findings |
| `session export/import` | Back up / restore a session as one JSON file |
| `import <type> <session> <file>` | Load endpoints (`auto` sniffs the format; `-` = stdin) |
| `export yaml <session> <out>` | Write a v1-compatible YAML template (`-` for stdout) |
| `doctor` | Sanity + credential-permission audit |
| `config get/set/list/unset` | Global settings (proxy, concurrency, timeout, output, color, retries, follow_redirects, user_agent) |
| `completion bash/zsh/fish` | Shell completion script |

Global flags: `-q/--quiet`, `-v/--verbose`, `--no-color/--color`, `-y/--yes`.

### Building credentials fast

```bash
# straight from a browser/Burp "Copy as cURL"
authz0 cred add shop admin --from-curl "curl 'https://shop/' -H 'Authorization: Bearer …' -b 'sid=…'"
# from captured traffic (HAR)
authz0 cred add shop admin --from-har ./capture.har
# HTTP Basic
authz0 cred add shop ops --basic 'ops:s3cret'
```

### Scan options (highlights)

```
--anon                 also probe each target with no auth (catches public exposure)
--severity high|low    show only findings of one severity (high=unauthorized, low=over-restrictive)
--sort severity        order rows findings-first (also: latency, status)
--tag T / --match GLOB scan only a subset of a large session
-L / --max-redirects N follow redirects
--retries N            retry transient failures (timeout/429/503)
--extra-header "K: V"  header sent with every probe/role
--proxy http://u:p@h   route through an (optionally authenticated) proxy
--dry-run              preview the probe matrix without sending requests
--baseline latest      diff against the session's last scan; --only-new / --fail-on-new
-o FORMAT / --save F   table|plain|json|markdown|sarif|html|csv (file format inferred from extension)
--fail-on-findings     non-zero exit for CI
```

A finding is split by severity: **unauthorized** (a role reached a resource it
shouldn't — the real breach, SARIF `error`) vs **over-restrictive** (a role was
denied access it should have — a functional bug, SARIF `warning`).

### How a verdict is decided

For each `(url, role)` pair authz0 sends the request with that role's
headers/cookies and asks the **assertions** whether the resource was accessed
(negative signals like `fail-status`/`fail-regex` win over a 200). It compares
that observation to the **expected** access for the role:

- expected access = role is in `allow-role` (or `allow-role` is empty) **and** not in `deny-role`
- a URL with neither allow nor deny roles has no policy to test (never a finding)
- mismatch ⇒ `X` (finding); match ⇒ `O`; request error ⇒ `?`

`scan` exits `1` only with `--fail-on-findings` (handy for CI); otherwise `0`.

## CI / GitHub Action

For one-shot scans (no persistent session), point `scan` at a v1-compatible
YAML template — ideal for pipelines:

```bash
authz0 scan --template authz0.yaml --output sarif --save authz0.sarif --fail-on-findings
```

The published GitHub Action wraps exactly that and produces a SARIF file you can
upload to GitHub code scanning:

```yaml
# .github/workflows/authz0.yml
name: authz0
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # for the SARIF upload
    steps:
      - uses: actions/checkout@v6
      - uses: hahwul/authz0@v2
        with:
          template: authz0.yaml      # a v1-compatible template in your repo
          output: sarif
          output_file: authz0.sarif
          fail_on_findings: "false"
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: authz0.sarif
```

Keep secrets out of the committed template by using `env:NAME` / `${NAME}`
header values (resolved from the job environment).

## Storage layout

```
~/.authz0/
├── config.json
└── sessions/<name>/
    ├── session.json     # metadata
    ├── urls.json        # endpoints
    ├── creds.json       # credentials (chmod 600, gitignored)
    ├── asserts.json     # detection rules
    ├── results/         # timestamped scan archives
    ├── exports/
    └── .gitignore       # excludes creds.json + results/
```

Override the root with `AUTHZ0_HOME`.

## Security notes

Credentials are stored in plaintext (acknowledged trade-off) but handled
carefully: `creds.json` is `chmod 600`, masked in every report and `cred list`
(use `--reveal` to see them), kept out of git via the auto-generated
`.gitignore`, and audited by `authz0 doctor`. Prefer `env:NAME` / `${NAME}`
header values so tokens never touch your shell history.

## Development

```bash
crystal spec                       # run the suite (unit + live-server integration)
crystal build src/main.cr -o authz0
crystal tool format src spec
```

## Contributing

1. Fork it (<https://github.com/hahwul/authz0/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## License

MIT — see [LICENSE](LICENSE).
