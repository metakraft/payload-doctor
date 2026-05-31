---
name: payload-doctor
description: Static security and correctness auditor for Payload CMS projects. Use this skill whenever working on Payload CMS access control, collection configuration, hooks, custom endpoints, Next.js route handlers or server actions that read or write Payload data, or before merging any user-data route. Run it after generating or changing Payload code to catch access-control bypasses and related anti-patterns. Trigger on "Payload security", "Payload access control", "overrideAccess", "Local API bypass", "audit Payload", "Payload doctor", "is this Payload collection secure", "check my Payload config", "cron fail closed", "force ownership on create", "side-effect GET", or any request to review the security of a Payload collection, hook, endpoint or route.
---

# payload-doctor

A CLI that statically audits a Payload CMS project for security and correctness
anti-patterns and prints a 0-100 health score with file:line findings.

## How to run it

From the project root:

```bash
npx -y payload-doctor@latest . --verbose
```

Add `--json` for machine-readable output, `--min-score N` to enforce a threshold
in CI, `--list` to see all checks.

## Workflow

1. Run the doctor on the Payload project.
2. Fix `error`-severity findings first, then warnings.
3. Re-run and confirm the score climbed and the findings are gone.
4. Keep a clean git state before applying fixes.

Score bands: 75-100 great, 50-74 needs work, 0-49 critical. Exit code is non-zero
when any error is present.

## What it checks

Access control (Local API `overrideAccess` bypass, open access functions,
missing collection access, ownership not forced on create, user-writable
privileged fields), routes (fail-open cron/secret guards, side-effect GETs, error
leaks), config (hardcoded secrets, wide-open CORS) and privacy (token/hash fields
readable via API). See README for the full table.

## Interpreting findings

Findings are static heuristics tuned for low false-positives. Always confirm in
context. The most important rule is `local-api-override-access`: Payload's Local
API defaults to `overrideAccess: true`, which bypasses collection access control,
so request-context calls must pass `overrideAccess: false` and `user` (or verify
ownership manually).

---

By Leander M. von Kraft — www.metakraft.de · Tierramor Agency. MIT licensed, provided as-is without warranty.
