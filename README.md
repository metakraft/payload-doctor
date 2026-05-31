# payload-doctor

Static **security & correctness linter for [Payload CMS](https://payloadcms.com)** —
the TypeScript headless CMS. It scans your collections, access control, hooks,
routes and config for known anti-patterns — the kind that AI coding agents and
humans alike get wrong — and prints a **0–100 health score** with actionable findings.

> **Note:** this is for **Payload CMS** (the framework). It does *not* inspect or
> validate API request/response payloads (JSON/XML). If you came looking for that,
> this isn't it.

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

# big report? show only the per-rule rollup
npx -y payload-doctor@latest . --summary

# print a suggested fix per rule (never modifies files)
npx -y payload-doctor@latest . --fix

# fail a CI job if the score drops below a threshold
npx -y payload-doctor@latest . --min-score 80

# print the version
npx -y payload-doctor@latest --version
```

**Recommended workflow:** run it → fix the errors first → re-run and watch the
score climb. Keep a clean git state before applying fixes.

Score bands: **75–100 great · 50–74 needs work · 0–49 critical.**

The score is `max(0, 100 − 10·errors − 3·warnings)`; `info` findings don't affect
it. Ten or more errors floor it at `0` by design — once you're in the red, track
the dropping error/warning counts (and the per-rule summary) to gauge progress
rather than the score alone.

Exit code is `1` when any `error`-severity finding is present (or the score is
below `--min-score`), `0` otherwise — drop it straight into CI or a pre-commit
hook. Use `--no-exit-code` while you're adopting it.

## Suppressing intentional cases

Some findings are deliberate — an OAuth callback that writes on `GET`, a cron
job using `overrideAccess: true`. Silence them inline, ESLint-style:

```ts
// payload-doctor-disable-next-line local-api-override-access
await payload.update({ collection: 'jobs', id, data })

// payload-doctor-disable-line side-effect-in-get

// payload-doctor-disable side-effect-in-get   ← whole file; omit the rule to silence all
```

Rule names may be written with or without the `payload-doctor/` prefix. The
number of suppressed findings is reported so suppressions stay visible.

## Checks

| Rule | Category | Severity | What it catches |
|------|----------|----------|-----------------|
| `local-api-override-access` | security | error / warning | Local API call without `overrideAccess: false` — access control bypassed |
| `override-access-true-with-user` | security | error | `overrideAccess: true` while passing a `user` — control skipped on purpose |
| `collection-missing-access` | security | warning | Collection with no explicit `access` block |
| `open-access-function` | security | error / info | `access.{create,update,delete}` returns `true` (anyone can write) |
| `missing-owner-enforcement` | security | warning | User-owned collection that doesn't force ownership on create |
| `user-writable-privileged-field` | security | error | `roles` / `isAdmin` / … field without field-level `access.update` |
| `mass-assignment` | security | error/warning | Privileged field settable on create (auth collection, open create, no field `access.create`) |
| `cron-not-fail-closed` | security | error | Secret/cron guard that is fail-open when the secret is unset |
| `side-effect-in-get` | correctness | error | `GET` handler performs a write (prefetch / email scanners trigger it) |
| `leaks-error-message` | security | warning | Internal `error.message` / stack returned to the client |
| `hardcoded-secret` | security | error | Secret, key or connection string committed as a string literal |
| `wide-open-cors` | config | warning | CORS set to `'*'` |
| `token-field-readable` | privacy | warning | Token/hash/secret field exposed via API (no field-level `read`) |
| `unsafe-richtext-render` | rendering | info | `dangerouslySetInnerHTML` renders CMS/rich-text HTML — review the sink (source may or may not be sanitized) |
| `collection-missing-slug` | config | error | Collection/global config without a `slug` |
| `duplicate-slug` | config | error | Same slug on more than one collection/global |
| `hook-missing-return` | correctness | warning | Transforming hook (`beforeChange`/`afterRead`…) returns nothing |
| `admin-hidden-not-access` | security | warning | `admin.hidden` field with no field access — still returned by the API |
| `dependency-version-mismatch` | config | error | Mixed `payload` / `@payloadcms/*` versions in package.json |
| `relationship-missing-relationTo` | correctness | error | `relationship`/`upload` field without `relationTo` |
| `select-without-options` | correctness | error | `select`/`radio` field without `options` |
| `duplicate-field-name` | correctness | error | Two fields with the same `name` in one `fields` array |
| `auth-weak-config` | security | warning | Auth lockout disabled (`maxLoginAttempts: 0`) or very long `tokenExpiration` |
| `sensitive-data-logged` | security | warning | `console.*` logs a password/token/secret value |
| `reserved-field-name` | config | warning | Field/slug collides with a Payload-reserved or Mongo-illegal identifier |
| `excessive-max-depth` | config | warning | `maxDepth`/`defaultDepth` above 10 |
| `missing-index-on-filter-field` | config | info | Commonly-filtered field (email/slug/…) without `index: true` |
| `hook-n-plus-one` | correctness | warning | Local API read inside a loop / `map` (N+1 query) |
| `circular-relationship` | correctness | info | `relationship`/`upload` fields form a cycle (watch `maxDepth`) |

List them anytime with `npx -y payload-doctor@latest --list`.

> The checks are static heuristics, like any linter. They are tuned for low
> false-positives, but always review findings in context. Files under
> `migrations/`, `seeds/`, `scripts/` and tests are treated as trusted system
> code and skipped for the request-context rules.

## Use with AI coding agents

This repo ships a `SKILL.md`, so it works as an agent skill too:

```bash
npx skills add https://github.com/metakraft/payload-doctor --skill payload-doctor
```

Then your agent can run the doctor after generating Payload code, fix the
flagged issues, and re-run to verify — closing the gap between "AI writes code"
and "code ships".

## Contributing

A check is a small object implementing the `Check` interface (see `src/types.ts`)
that receives a `ts-morph` `SourceFile` and returns `Finding[]`. Add yours to the
relevant file in `src/checks/` and register it in `src/checks/index.ts`. There are
self-test fixtures in `test/fixtures/` — an intentionally insecure project
(`vulnerable`), a secure reference (`clean`), and a `tricky` set of legitimate
patterns that must NOT produce findings (the false-positive guard). Build and run
the assertion suite with:

```bash
npm install
npm test
```

`npm test` builds the project and asserts that `vulnerable` is flagged while
`clean` and `tricky` stay silent. Add a fixture whenever you add or change a
check, and keep the false-positive rate low — a noisy linter gets disabled.

PRs that add checks, reduce false-positives, or add fixtures are welcome.

## Bugs & feature requests

Please use **[GitHub Issues](https://github.com/metakraft/payload-doctor/issues)** —
there are templates for bug reports (incl. false positives) and new-check requests.
Open-ended questions and "show & tell" go in
**[Discussions](https://github.com/metakraft/payload-doctor/discussions)**; suspected
security issues via a private **Security Advisory** (see `SECURITY.md`). `npm bugs`
from a project using the package opens the issue tracker directly.

## Author

Leander M. von Kraft — [www.metakraft.de](https://www.metakraft.de)
Tierramor Agency — AI-native project work.

## Disclaimer

Provided as-is, free and open source, **without warranty or any obligation** —
no support, no guarantees, no liability. The checks are static heuristics: they
help, but you remain responsible for reviewing findings and securing your own
code. Use at your own risk.

## License

[MIT](./LICENSE). Free to use, modify and distribute. No rights reserved beyond
the attribution the MIT license asks for.
