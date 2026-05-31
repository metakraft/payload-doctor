# Changelog

All notable changes to this project are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com).

## 0.5.4

Minor polish from a second-pass review. No behaviour change on findings (fixtures still 0 FP).

### Changed
- `--fix` header now states the file count: `5× in 3 files — a.ts (3), b.ts (2)`.

### Docs
- Reframed the `returnsTrue()` non-goal as scope demarcation (a hypothetical
  `always-truthy-expression` check is a separate concern), not risk-avoidance.

## 0.5.3

Closeout of the v0.5.2 code-review feedback (review rated 5/5). No behaviour change on
real projects (fixtures unchanged: 0 false positives).

### Changed
- `--fix` groups locations by file (`5× — a.ts (3), b.ts (2), +1 more`) instead of showing
  only the first occurrence — easier to see where a rule actually fires.
- Context-specific fix snippets extended beyond the `mass-assignment` pilot to
  `missing-owner-enforcement` (names the slug and the owner field in a beforeChange stamp),
  `collection-missing-access` (names the slug), and `reserved-field-name` (names the field).

### Docs
- Clarified that the self-loop check in cycle detection is intentional: Tarjan places a
  self-referencing node in a size-1 SCC, so an SCC-size test alone would miss real self-loops.
- Documented a non-goal: `returnsTrue()` matches only a literal `true`, not constant-folded
  expressions like `() => (!false)` (vanishingly rare, and folding would add FP risk).

## 0.5.2

Hardening from an external code review (rated 4.8/5, production-ready). All P0 and P1
items addressed; behaviour of the checks is unchanged on real projects (still 0 FPs on
the test fixtures). P2 ideas backlogged.

### Fixed (P0)
- CLI: `--min-score` now validates its argument (must be a number 0–100) and exits with a
  clear message otherwise, instead of silently using `NaN`.
- CLI: the ts-morph project setup is wrapped in error handling, and an empty scan (no
  `.ts/.tsx/.js/.jsx` files under the path) now prints a helpful message and exits 2
  instead of silently scanning nothing.

### Changed (P1)
- Cycle detection (`circular-relationship`) now uses Tarjan's SCC — O(V+E) instead of a
  per-node DFS — so it scales to large relationship graphs. Output is unchanged.
- `package.json` parsing in `dependency-version-mismatch` is defensively validated
  (non-object root, non-object `dependencies`, non-string version specs are skipped, never throw).
- `returnsTrue()` is now AST-based instead of regex: it matches only an *unconditional*
  `() => true` / `() => { return true }`, so it no longer false-matches on `() => true && x`
  or a `return true` guarded by an `if`. More precise open-access detection.
- `--fix` output is now context-aware: each rule shows where it fires (`file:line`, with a
  count) and checks can supply a context-specific snippet — e.g. `mass-assignment` names the
  actual field and collection in its suggested field-level `access.create`.

## 0.5.1

Staying on **0.5.x** until the checks run cleanly across many more real projects
(target: ~10 more real-world runs before any 0.6/1.0). Data-driven against real
a real 285-file Payload project.

### Added
- `mass-assignment` (security, error/warning): an **auth** collection with open
  `create` (public or any authenticated user) and a privileged field
  (`roles`/`isAdmin`/…) lacking field-level `access.create` and a sanitizing
  beforeChange hook — a registrant could send `roles: ['admin']` on create.
  Scoped to auth collections; complements `user-writable-privileged-field` (update path).

### Changed (false-positive & severity tuning from real runs)
- `local-api-override-access`: server/job context (cron, webhooks, sync/worker/job
  files, migrations) → `info` (the Local API default is expected there). User-facing
  routes/actions unchanged.
- `missing-owner-enforcement`: admin/system-restricted `create` → `info` (system stamps
  the owner). User-facing create incl. `ownerOrAdmin` stays `warning`.
- `unsafe-richtext-render`: `warning` → `info` (a static tool can't prove the HTML source
  is sanitized; it's an audit pointer).
- `reserved-field-name`: (a) only checks objects inside a real `fields: [...]` array, so
  raw-query aliases like `{ name: 'm.name' }` are no longer flagged; (b) ignores reserved
  names on fields nested in `array`/`blocks`/`group` (array rows legitimately carry `id`).
  Mongo-illegal `.`/`$` still flagged for real fields at any depth.
- `hook-n-plus-one`: fixed (string-literal) collection → `warning` (batchable N+1);
  dynamic collection per item → `info` (likely heterogeneous, not trivially batchable).
- `hardcoded-secret`: in trusted system paths (seed/migrations/scripts) → `info`, so a
  dev/seed default doesn't tank the score.

### Severity columns
- The per-rule Summary shows an `Xe/Yw/Zi` breakdown, in the text report and `--json`.

Total: 29 rules (26 per-file in `--list` + duplicate-slug, dependency-version-mismatch,
circular-relationship cross-file).

Deferred (need real-world validation, likely FP-prone or out of static scope):
`missing-rate-limit` (limiting often lives in middleware/infra), `exposed-admin-api`
(admin exposure is a deploy/infra concern, not visible in TS source).

## 0.5.0

### Added
- **Security depth:**
  - `auth-weak-config` (warning): auth lockout disabled (`maxLoginAttempts: 0`) or a
    `tokenExpiration` over 30 days. Only flags explicit weakenings — Payload's defaults
    are safe, so a *missing* option is not flagged.
  - `sensitive-data-logged` (warning): a `console.*` call that logs a password/token/
    secret/apiKey/ssn/cvv value.
- **Schema & performance hygiene:**
  - `reserved-field-name` (warning): a field name colliding with Payload-reserved fields
    (`id`/`_id`/`createdAt`/`updatedAt`/`_status`/…) or illegal in MongoDB (`.`/`$`), and
    collection slugs colliding with `payload-*` internals. Generic SQL keywords are NOT
    flagged — the SQL adapter quotes identifiers, so they work.
  - `excessive-max-depth` (warning): `maxDepth`/`defaultDepth` above 10.
  - `missing-index-on-filter-field` (info): a commonly-filtered field (email/slug/username/
    externalId/sku) without `index: true`.
  - `hook-n-plus-one` (warning): a Local API read (`find`/`findByID`/`findGlobal`) inside a
    loop or `map`/`forEach`/… callback — the classic N+1.
  - `circular-relationship` (info, cross-file): relationship/upload fields forming a cycle
    (A → B → A or self). Cycles are often legitimate, so it's an info reminder to bound `maxDepth`.
- The per-rule **Summary** now shows a severity breakdown per rule, e.g. `(6e/35w/17i)`,
  in both the text report and the `--json` `summary` field.

Total: 28 rules (25 per-file in `--list` + duplicate-slug, dependency-version-mismatch,
circular-relationship as cross-file passes).

## 0.4.1

### Changed
- **Summary by rule now prints at the TOP** of the report (was at the bottom) — the
  overview is visible without scrolling past every finding.
- `side-effect-in-get` is downgraded to `warning` on `unsubscribe`/`opt-out` routes
  (email one-click unsubscribe is a GET convention), with a note about mail-client
  prefetch and RFC 8058 List-Unsubscribe-Post. Cron stays `info`, everything else `error`.

### Added
- `--json` output now includes a `summary` array (per-rule rollup: ruleId, severity,
  count, files). JSON `schema` bumped to `2`.
- Documented the score formula in `--help` and the README:
  `max(0, 100 − 10·errors − 3·warnings)`; info findings don't affect it.

## 0.4.0

### Added
- Four new static checks:
  - **`dependency-version-mismatch`** (config, error): reads `package.json` and
    flags mixed `payload` / `@payloadcms/*` versions — a top cause of mysterious
    build/runtime breaks. Skips ranges/tags/`workspace:*` it can't compare.
  - **`relationship-missing-relationTo`** (correctness, error): a `relationship`
    or `upload` field without `relationTo`.
  - **`select-without-options`** (correctness, error): a `select`/`radio` field
    without `options`.
  - **`duplicate-field-name`** (correctness, error): two fields with the same
    `name` in the same `fields` array (per-array namespace, no cross-namespace FPs).

## 0.3.1

### Added
- Four new checks:
  - **`collection-missing-slug`** (config, error): a collection/global config
    with `fields` but no `slug`. Only high-confidence configs are flagged
    (inline `collections:`/`globals:` array elements, or objects typed
    `CollectionConfig`/`GlobalConfig`), so nested field groups and tabs are safe.
  - **`hook-missing-return`** (correctness, warning): a transforming hook
    (`beforeChange`/`beforeValidate`/`beforeRead`/`afterRead`/`beforeDuplicate`)
    that never returns a value — Payload uses the return value, so the change is
    silently dropped. Side-effect-only hooks (`afterChange`…) are not flagged.
  - **`duplicate-slug`** (config, error): the same slug on more than one
    collection/global (cross-file check).
  - **`admin-hidden-not-access`** (security, warning): a field with
    `admin.hidden: true` and no field-level `access` — it is hidden in the Admin
    UI but still returned by the REST/GraphQL API.
- **`--fix`**: prints a suggested fix snippet per rule. It never modifies files.

### Changed
- Sharpened the tagline/description to make clear this is for **Payload CMS**
  (the framework), not for validating API request/response payloads.

## 0.3.0

### Added
- **`unsafe-richtext-render` check** (new `rendering` category): flags
  `dangerouslySetInnerHTML` rendering CMS/rich-text content without visible
  sanitization — the block-render seam where stored XSS hides. Only fires on
  content that looks CMS-related (generic React stays out of scope).
- **`--summary`** flag and an always-on "Summary by rule" rollup (count +
  distinct files per rule), so large reports don't scroll forever.

### Changed
- Score weighting: `error=10`, `warning=3`, **`info=0`** (info findings no longer
  drag the score down).
- `side-effect-in-get` is downgraded to `info` inside `/cron/` routes (Vercel
  cron requires GET); a reminder to keep the write idempotent is included.

## 0.2.3

### Changed
- Repository/author links now point to `github.com/metakraft`.

## 0.2.2

### Fixed
- A non-existent target path now prints a clear `Path not found:` error and exits
  with code 2, instead of the ambiguous "No source files found" message.

### Added
- Scanning a single file (not just a directory) is now supported.

## 0.2.1

### Added
- Author / maintainer attribution (Leander M. von Kraft — Tierramor Agency) in
  README, SKILL.md and `package.json`.
- `package.json` metadata: `author`, `homepage`, `repository`, `bugs`.
- `SECURITY.md`, `CONTRIBUTING.md`, and a GitHub Actions CI workflow that runs
  `npm test` on Node 18/20/22.
- README disclaimer: provided as-is, free and open source, without warranty or
  support obligation.

## 0.2.0

Tuned against a real-world Payload project to cut false positives.

### Fixed (false positives)
- **Blocks and globals are no longer mistaken for collections.** A new config
  classifier uses array position, type annotation (`CollectionConfig` / `Block` /
  `GlobalConfig`) and file path, and treats anything nested inside a `fields`
  array as a block. This stops `collection-missing-access`, `open-access-function`,
  `missing-owner-enforcement`, `user-writable-privileged-field` and
  `token-field-readable` from firing on blocks.
- **Public registration** (`create: () => true` on an `auth` collection) is now
  `info`, not `error`.
- **Explicit system writes** (`overrideAccess: true` with no `user`, e.g. cron /
  webhooks) are now `info` instead of `error`; `overrideAccess: true` together
  with a `user` is still reported by `override-access-true-with-user` (no double
  reporting).

### Added
- **Inline suppression** (ESLint-style): `// payload-doctor-disable-next-line`,
  `// payload-doctor-disable-line`, `// payload-doctor-disable` — optionally
  scoped to specific rule ids, or all rules when none is given. Suppressed count
  is shown in text and JSON output.
- `-V` / `--version` flag; version printed in the report header, `--help`, and as
  `toolVersion` in JSON.
- Self-test fixtures for blocks, suppression and system writes.

## 0.1.0

Initial release.

### Checks
- Access control: `local-api-override-access`, `override-access-true-with-user`,
  `collection-missing-access`, `open-access-function`, `missing-owner-enforcement`,
  `user-writable-privileged-field`.
- Routes: `cron-not-fail-closed`, `side-effect-in-get`, `leaks-error-message`.
- Config & privacy: `hardcoded-secret`, `wide-open-cors`, `token-field-readable`.

### Tooling
- 0-100 health score with `great` / `needs-work` / `critical` bands.
- Text and `--json` output, `--verbose` hints, `--list`, `--min-score`,
  `--no-exit-code`, `--no-color`. CI-friendly exit codes.
- Auto-detects `.ts/.tsx/.js/.jsx`; skips `node_modules`, `dist`, `.next`,
  `build` and treats `migrations/seeds/scripts/tests` as trusted system code.

### False-positive hardening
- Word-segment matching (camelCase aware) so `hashtags`/`tokenizer` no longer
  match the `hash`/`token` sensitive-field rule.
- Tightened the error-leak regex so identifiers like `code.message` /
  `response.message` are no longer mistaken for `error.message`.
- `local-api-override-access` skips calls whose options object uses a spread
  (the spread may carry `overrideAccess: false`).
- `missing-owner-enforcement` no longer fires when a `beforeValidate`/
  `beforeChange` hook is present (it may be imported) or the owner field has a
  `defaultValue`.
- Dropped speculative field names (`plan`, `tier`) from the privileged-field rule.

### Tests
- Self-test fixtures: `vulnerable` (must be flagged), `clean` and `tricky`
  (must produce zero findings). Run with `npm test`.
