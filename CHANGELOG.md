# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [2.0.0] — Crystal rewrite

A complete, session-based rewrite of authz0 in Crystal, replacing the v1 Go tool.

### Added — workflow

- **Session model** — incremental `session` / `url` / `cred` / `assert` commands
  backed by plain JSON under `~/.authz0/sessions/<name>/` (`creds.json` is `chmod 600`).
- **One-shot scans** — `scan --template <v1.yaml>` runs ephemerally with no session
  (CI-friendly, and reads authz0 v1 templates).
- **`results`** — list / show / clean archived scans. **`stats`** — cross-session
  overview with open-finding counts. **`session export/import`** — portable JSON backup.

### Added — scanning

- Concurrent fiber-based scanner (proven data-race-free under `-Dpreview_mt`).
- Assertions: `success-status` / `fail-status` (exact codes **or** `2xx`/`4xx`
  classes), `fail-regex`, `fail-size` (+margin), `success-header` / `fail-header`.
- Redirect following (`-L`), retries (`--retries`), `--user-agent`, `--extra-header`,
  `--anon` baseline, authenticated proxy (`--proxy http://u:p@host`), `--dry-run`.
- `--baseline` regression diff (`--only-new` / `--fail-on-new`), `--tag` / `--match`
  scoping, `--severity` / `--sort` triage, per-probe latency.

### Added — credentials

- `cred --from-curl` (browser/Burp "Copy as cURL"), `cred --from-har`
  (extract auth from captured traffic), `cred --basic user:pass`,
  `env:NAME` / `${NAME}` value injection.

### Added — imports & reports

- Imports: OpenAPI/Swagger, HAR, Burp XML, Postman (with `{{variable}}`), URL lists,
  `import auto` (sniffs the format), and stdin (`-`).
- Reports: table, plain, JSON, Markdown, CSV, **SARIF 2.1.0** (with stable
  fingerprints), self-contained **HTML** — file format inferred from `--save` extension.
- **Finding severity split:** unauthorized-access (real breach, SARIF `error`) vs
  over-restrictive (functional, SARIF `warning`).

### Security

- Credential masking everywhere except `--reveal`; atomic 0600 credential writes;
  auto-generated `.gitignore`; path-traversal guards on every session operation;
  `doctor` audits permissions and session health.

### Distribution

- GitHub Action (SARIF output), Docker/GHCR, Homebrew, AUR, Snapcraft,
  `.deb`/`.rpm`/`.apk`, CycloneDX SBOM, and CI (build · format · ameba · tests ·
  multi-threaded tests · docker · snap).
