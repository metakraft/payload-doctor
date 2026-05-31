# Security Policy

`payload-doctor` is a static analysis tool; it reads source files and does not
execute project code, send data anywhere, or require credentials.

## Reporting a vulnerability

If you find a security issue in the tool itself (for example, a way to make it
execute untrusted input), please report it privately rather than opening a public
issue:

- Use GitHub's "Report a vulnerability" (Security advisories) on the repository, or
- Reach out via the contact on [www.metakraft.de](https://www.metakraft.de).

For false positives / false negatives in the checks, a normal GitHub issue is
perfect.

## Scope & expectations

This project is provided as-is, without warranty or any support obligation
(see the [LICENSE](./LICENSE)). Findings are heuristics — always review them in
context. The tool is an aid, not a guarantee of security.
