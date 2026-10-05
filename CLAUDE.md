# ghgw

GitHub gateway for coding agents. `SPEC.md` is the source of truth for behavior: read it first and
update it in the same change when behavior changes.

## Rules

- Everything in the repo is in English: code, comments, docs, commits, PRs.
- Commits and PR titles: `<scope>: <description>`, imperative, lowercase, no trailing period, up to
  72 characters. Scope is the area touched: `core`, `gateway`, `adminapi`, `store`, `setup`,
  `cli`, `docs`, `build`. Example: `gateway: reject pushes to the default branch`.
- No AI attribution anywhere: no `Co-Authored-By` trailers, "Generated with" lines, session links
  or model names in commits, PRs, code or docs.
- Work incrementally, one step at a time; discuss design changes before coding them.
- Keep it clean and concise: when something replaces old code, delete the old path in the same
  change. No dead code, no compatibility shims, no commented-out leftovers.

## Code

- Go, current stable release. `gofmt`, `go vet` and the tests pass before every commit.
- Follow the layout in SPEC.md: `internal/core` has no HTTP; transports stay thin.
- Standard library first. Each dependency must earn its place (cobra, charm, modernc sqlite).
- Pass `context.Context` through; every network call has a timeout.
- Errors tell the caller what to do next (SPEC.md section 8).
- Comments explain why, not what.
- Tests: table-driven; GitHub is faked with recorded fixtures; end-to-end tests only run when a
  test token is present in the environment.

## Security

- Never log, print or commit secrets: GitHub tokens, ghgw keys, admin tokens, the master key.
- ghgw keys and admin tokens are stored hashed; GitHub credentials are encrypted at rest.
- Secrets enter through stdin, files or environment variables, never command-line arguments.
