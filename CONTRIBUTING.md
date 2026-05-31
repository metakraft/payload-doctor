# Contributing

Contributions are welcome — especially new checks, false-positive fixes, and
fixtures.

## Setup

```bash
npm install
npm test     # builds, then asserts the fixtures
```

## Adding a check

A check is a small object implementing the `Check` interface (`src/types.ts`)
that receives a `ts-morph` `SourceFile` and returns `Finding[]`. Add it to the
relevant file in `src/checks/` and register it in `src/checks/index.ts`.

Then add fixtures under `test/fixtures/`:

- `vulnerable/` — code your check should flag.
- `clean/` and `tricky/` — legitimate code your check must NOT flag.

Run `npm test` and make sure all cases pass. Keep the false-positive rate low —
a noisy linter gets disabled. When in doubt, prefer a lower severity (`warning`
or `info`) and a clear fix hint.

## Style

TypeScript, strict mode. Findings should carry a precise `file:line`, a concise
message, and an actionable `hint`.

## License

By contributing you agree your contributions are licensed under the project's
[MIT License](./LICENSE).
