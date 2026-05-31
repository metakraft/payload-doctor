# payload-doctor

Static **security & correctness auditor for [Payload CMS](https://payloadcms.com) projects.**
It scans your collections, access control, hooks, routes and config for known
anti-patterns — the kind that AI coding agents and humans alike get wrong — and
prints a **0–100 health score** with actionable findings.

Think of it as a `react-doctor` for Payload. One command, no install:

```bash
npx -y payload-doctor@latest .
```

## Why

Payload's **Local API bypasses access control by default** (`overrideAccess` is
`true` unless you set it to `false`). It's the single most expensive footgun in a
Payload app: a route can authenticate a user and still hand them someone else's
records, because the collection's `access` functions never run. payload-doctor
catches that and a dozen related issues before they reach production.

## Usage

```bash
# scan the current project
npx -y payload-doctor@latest .

# show fix hints
npx -y payload-doctor@latest . --verbose

# machine-readable output for CI / dashboards
npx -y payload-doctor@latest . --json

# fail a CI job if the score drops below a threshold
npx -y payload-doctor@latest . --min-score 80
```

**Recommended workflow:** run it → fix the errors first → re-run and watch the
score climb. Keep a clean git state before applying fixes.

Score bands: **75–100 great · 50–74 needs work · 0–49 critical.**

Exit code is `1` when any `error`-severity finding is present (or the score is
below `--min-score`), `0` otherwise — drop it straight into CI or a pre-commit
hook. Use `--no-exit-code` while you're adopting it.

## Checks

| Rule | Category | Severity | What it catches |
|------|----------|----------|-----------------|
| `local-api-override-access` | security | error / warning | Local API call without `overrideAccess: false` — access control bypassed |
| `override-access-true-with-user` | security | error | `overrideAccess: true` while passing a `user` — control skipped on purpose |
| `collection-missing-access` | security | warning | Collection with no explicit `access` block |
| `open-access-function` | security | error / info | `access.{create,update,delete}` returns `true` (anyone can write) |
| `missing-owner-enforcement` | security | warning | User-owned collection that doesn't force ownership on create |
| `user-writable-privileged-field` | security | error | `roles` / `isAdmin` / … field without field-level `access.update` |
| `cron-not-fail-closed` | security | error | Secret/cron guard that is fail-open when the secret is unset |
| `side-effect-in-get` | correctness | error | `GET` handler performs a write (prefetch / email scanners trigger it) |
| `leaks-error-message` | security | warning | Internal `error.message` / stack returned to the client |
| `hardcoded-secret` | security | error | Secret, key or connection string committed as a string literal |
| `wide-open-cors` | config | warning | CORS set to `'*'` |
| `token-field-readable` | privacy | warning | Token/hash/secret field exposed via API (no field-level `read`) |

List them anytime with `npx -y payload-doctor@latest --list`.

> The checks are static heuristics, like any linter. They are tuned for low
> false-positives, but always review findings in context. Files under
> `migrations/`, `seeds/`, `scripts/` and tests are treated as trusted system
> code and skipped for the request-context rules.

## Use with AI coding agents

This repo ships a `SKILL.md`, so it works as an agent skill too:

```bash
npx skills add https://github.com/OWNER/payload-doctor --skill payload-doctor
```

Then your agent can run the doctor after generating Payload code, fix the
flagged issues, and re-run to verify — closing the gap between "AI writes code"
and "code ships".

## Contributing

A check is a small object implementing the `Check` interface (see `src/types.ts`)
that receives a `ts-morph` `SourceFile` and returns `Finding[]`. Add yours to the
relevant file in `src/checks/` and register it in `src/checks/index.ts`. There are
self-test fixtures in `test/fixtures/` — an intentionally insecure project and a
secure reference. Build and run them with:

```bash
npm install
npm run build
npm run selftest
```

PRs that add checks, reduce false-positives, or add fixtures are welcome.

## License

MIT — see [LICENSE](./LICENSE).
