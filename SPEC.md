# ghgw: GitHub gateway for coding agents

Status: draft (v0 scope). This document is the source of truth for behavior; change it together
with the code.

## 1. Problem

Coding agents (Claude Code, Codex, ...) need `git` and `gh` against GitHub. Any token placed in
the agent's environment can be read and exfiltrated by the agent itself, for example through
prompt injection. Fine-grained personal access tokens (PATs) are also scoped to a single resource
owner (a user or an organization), so an agent that works across owners needs several of them.

## 2. Solution

ghgw sits between agents and GitHub and holds the real credentials. Each agent gets its own ghgw
key, which is useless anywhere but the gateway. For every request ghgw:

1. authenticates the ghgw user (the agent),
2. decides whether the policy allows the operation on that repository,
3. picks the credential of the repository's owner and injects it,
4. forwards the request to GitHub,
5. writes an audit record.

Agents keep using plain `git` and `gh`: `git` is redirected with `url.<base>.insteadOf`, and `gh`
treats the gateway as a GitHub Enterprise host. `ghgw setup` configures both.

### Goals

- Agents never hold a GitHub credential.
- Per-user and per-group policy: repositories, read/write, pushable branches, allowed API
  operations. Deny by default.
- Several resource owners, one credential each, chosen per request.
- Transparent for `git` and `gh`; one-command client setup.
- Errors that tell the agent what to do instead (section 8).
- One static binary (gateway, admin CLI and client setup), easy to self-host, amd64 and arm64.

### Non-goals

- Reimplementing the GitHub API: ghgw forwards to GitHub and only filters.
- Being a git server, mirror or cache.
- GitHub Enterprise Server upstreams (v0).
- A web UI (v0). The admin API is designed so one can be added (section 9).

## 3. Concepts

| Concept | Meaning |
|---|---|
| **User** | An identity that calls the gateway: an agent (`rpi01-agent`), one day a person. Has a ghgw key. |
| **Group** | A named set of users. Grants given to a group apply to all its members. |
| **Grant** | Allows a set of repositories with an access level, push branches and an API preset. Attached to a user or a group. |
| **Owner** | A GitHub user or organization. Has one credential (a fine-grained PAT in v0). |
| **Credential** | The real GitHub token for an owner. Never leaves the gateway. Behind an interface so a GitHub App can be added later. |
| **Admin** | Whoever manages users, groups, grants and owners through the admin API. |

## 4. Architecture

```
 agents                                                        admin
 ┌──────────────────────────────┐                  ┌───────────────────────────────┐
 │ git ──insteadOf──┐           │                  │ ghgw user|group|grant|... CLI │
 │ gh ──Ent. host───┤           │                  │ (later: MCP, web UI)          │
 │ ghgw credential ─┘ (key)     │                  └───────────────┬───────────────┘
 │ ghgw setup / doctor          │                                  │ HTTPS + admin token
 └───────────────┬──────────────┘                                  │
                 │ HTTPS                                           │
┌────────────────┼──────────────────────── ghgw serve ─────────────┼────────────────────┐
│                ▼                                                 ▼                    │
│  ┌─ gateway listener ───────────────────┐      ┌─ admin listener ──────────────────┐  │
│  │ /<owner>/<repo>.git/...  git proxy   │      │ /admin/v1/...   JSON API          │  │
│  │ /api/v3/*                REST proxy  │      └─────────────────┬─────────────────┘  │
│  │ /api/graphql             guidance   │                        │                    │
│  │ /_ghgw/*                 whoami ...  │                        │                    │
│  └───────────────┬──────────────────────┘                        │                    │
│                  ▼                                               ▼                    │
│  ┌──────────────────────────────── core ───────────────────────────────────────────┐  │
│  │ Users, Groups, Grants, Owners/Credentials, Audit                                │  │
│  │ Decide(user, owner/repo, operation) → allow/deny + reason + credential          │  │
│  └───────────────┬──────────────────────────────────────────────┬──────────────────┘  │
│                  ▼                                              ▼                     │
│  ┌─ store: SQLite ─────────────────┐            ┌─ upstream: github.com ──────────┐   │
│  └─────────────────────────────────┘            └─────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

The two listeners are separate on purpose: the admin listener must never be reachable by the
agents it governs.

### Code layout

```
cmd/ghgw/            cobra commands (serve, admin commands, setup, credential, doctor)
internal/core/       domain and decisions; no HTTP; testable on its own
internal/gateway/    git and REST proxies; calls core
internal/adminapi/   thin HTTP handlers over core
internal/store/      state directory: SQLite (modernc.org/sqlite: pure Go, no cgo), master key, sealed credentials
internal/setup/      client side: git and gh configuration, undo, doctor
pkg/api/             request/response types shared by the admin API and its clients
pkg/adminclient/     Go client of the admin API (used by the CLI; later the MCP server)
```

## 5. Gateway

All paths are on the gateway listener, over HTTPS (`gh` refuses plain HTTP for Enterprise hosts).
`/_ghgw/` is reserved for ghgw's own endpoints.

### 5.1 Authentication

The ghgw key is accepted as:

- HTTP Basic password (git, through the `ghgw credential` helper; the username is ignored),
- `Authorization: token <key>` or `Bearer <key>` (`gh`).

Keys are `ghgw_` and 64 lowercase hex characters (256 random bits) and are stored only as SHA-256
hashes: a key is shown once, when it is created or rotated. A key is looked up by the first 8
bytes of its hash and then compared in full in constant time. A missing or unknown key gets a 401
that names `ghgw setup` (section 8).

### 5.2 git (smart HTTP)

- `GET /<owner>/<repo>.git/info/refs?service=git-upload-pack|git-receive-pack`,
  `POST /<owner>/<repo>.git/git-upload-pack`, `POST /<owner>/<repo>.git/git-receive-pack`
  (the `.git` suffix is optional, as on GitHub; repository names ending in `.git` are therefore
  rejected, so `/o/x.git` always means repository `x`).
- Forwarded to `https://github.com/<owner>/<repo>.git/...` with the owner's credential as Basic
  auth (`x-access-token:<token>`). Bodies are streamed, never buffered whole.
- Fetch and clone (`upload-pack`) need `read`. Push (`receive-pack`) needs `write`; the
  receive-pack ref advertisement checks only that, and the push itself is checked ref by ref.

Push checks read the ref update commands (pkt-lines before the pack) and reject the push if any
command is not allowed:

| Update | Rule |
|---|---|
| Branch create or update | Branch must match a `push` glob of an effective grant with `access: write` for the repository. |
| Branch delete | Same glob rule (agents may clean up their own branches). |
| Default branch | Never, whatever the grants say (hard rule). Compared case-insensitively. |
| Tags | Never in v0 (hard rule). |
| Other refs (`refs/notes/...`, anything outside `refs/heads/`) | Never in v0 (hard rule). |
| Invalid ref names (`git check-ref-format`) | Never. |

If the default branch cannot be looked up or is not a valid branch name, the push is rejected: the
hard rule cannot be checked. A push without ref update commands is rejected too, and so is a push
with more than 1000 ref updates or with a ref name longer than 1024 bytes; transports enforce these
limits while parsing, before holding the commands in memory. A push over 1000 updates is rejected as
a whole, without a result per ref, whatever else is wrong with it. Refs and other names from the
request or from policy input go through one renderer before they are shown anywhere (reasons,
errors, `ng` lines, `explain`): quoted when they contain anything but printable characters, and cut
after a whole character or escape so that the rendered name, with the length that follows a cut
name, is at most 1024 bytes.

A rejected push is answered by ghgw itself with a receive-pack report (`ng <ref> <reason>`, in the
sideband when negotiated) and nothing reaches GitHub. Pushes are all-or-nothing: if one ref is
rejected, the others are reported as `ng ... (another ref was rejected)`. Each ref gets a short
reason of its own; the guidance (allowed branches) is part of the push's reason, once, so the report
stays small whatever the policy holds.

Force pushes to allowed branches are allowed in v0 (agents rebase their own branches). The default
branch is looked up through the REST API and cached for a few minutes.

### 5.3 REST

- `/api/v3/<path>` is forwarded to `https://api.github.com/<path>` with the owner's credential.
- The owner and repository come from the path (`/repos/{owner}/{repo}/...`).
- Each request is classified as an operation (method + path template, e.g. `pulls.create`).
  Unknown operations are denied.
- `Link` headers (pagination) and `Location` headers are rewritten from `api.github.com` to the
  gateway, so `gh` never sends the ghgw key to GitHub. Response bodies are not rewritten.

API presets:

| Preset | Allows |
|---|---|
| `read` | `GET` on repository endpoints: contents, commits, branches, pulls, issues, comments, reviews, checks, Actions runs/jobs/logs, releases. |
| `pr` | `read` plus: create and update pull requests, pull request reviews and review comments, issues and issue comments, labels on issues and pulls, re-run of Actions jobs. |

A grant's `api` is `read`, `pr`, or omitted (no REST operation); `pr` includes `read`.

Always denied in v0 (hard rules):

- Code changes outside git push: contents writes, git data writes (`/git/refs`, trees, commits),
  branch merges and syncs. Every code change goes through the push checks in one place.
- Merging pull requests.
- Releases: creating one creates a tag, and tags cannot be pushed.
- CI results: commit statuses, check runs and check suites, which an agent could forge.
- Triggering workflows and deployments, which run with the repository's secrets. Re-running jobs
  stays in the `pr` preset.
- Repository administration: settings, transfer, forking, topics, collaborators, hooks, keys,
  secrets, variables, environments, rulesets, branch protection, Pages, autolinks, security
  settings, Actions settings (permissions, runners, OIDC, caches).
- Endpoints that are not repository-scoped (`/user`, `/orgs`, `/search`, ...), except
  `GET /rate_limit` and `GET /meta`.

The exact operation table lives in code (`internal/core`), with tests, and in `docs/operations.md`.
Each entry has a name, a method, a path template and exactly one class: `read` or `pr` (allowed by
that preset), `global` (allowed for every enabled user, no grant needed), or one of the hard rules
above (always denied, with that rule as the reason). `read` and `global` entries must be `GET`, and
only `GET /rate_limit` and `GET /meta` can be `global`.

The table is the allow-list. The hard rules are also enforced on their own, from method and path
families that do not depend on the table: an entry that falls in a family must have that family's
class (the table is rejected otherwise), and a request is denied by the family's rule whatever its
entry says. Path templates must be canonical (segments of lowercase letters, digits, `-` and `_`,
or whole-segment `{parameters}`; no escapes, dots, backslashes or delimiters), so a family cannot be
dodged by spelling. Parameters cannot hide a family either: the segment after
`/repos/{owner}/{repo}` is always literal, a parameter stands for any one segment, and a `read`,
`pr` or `global` template is rejected when some value of its parameters reaches a family
(`pulls/{n}/{action}` reaches the merge rule). The REST proxy (M7) checks the families again on the
concrete method and path of each request. The families, on paths under `/repos/{owner}/{repo}`
("writes" means any method but `GET`):

| Hard rule | Family |
|---|---|
| Code change | Writes under `contents/` and `git/`; writes to `merges`, `merge-upstream` and `pulls/{n}/update-branch` (they change branches without a push). |
| Merge | Writes to `pulls/{n}/merge`. |
| Release | Writes under `releases/` (assets included). |
| CI result | Writes under `statuses/`, `check-runs/` and `check-suites/`. |
| Trigger | Writes to `dispatches` and `actions/workflows/{id}/dispatches`; writes under `deployments/`. |
| Administration | Writes to the repository itself, `transfer`, `forks` and under `topics/`; writes to `branches/{branch}/rename`. Every method under `collaborators`, `invitations`, `hooks`, `keys`, `environments`, `rulesets`, `pages`, `autolinks`, `vulnerability-alerts`, `automated-security-fixes`, `private-vulnerability-reporting`, `actions/permissions`, `actions/runners`, `actions/runner-groups`, `actions/oidc`, `actions/cache`, `actions/caches`, `actions/secrets`, `actions/variables`, `actions/organization-secrets`, `actions/organization-variables`, `dependabot/secrets` and `codespaces/secrets` (environment secrets and variables are under `environments`), and on `branches/{branch}/protection`. |
| Not repository-scoped | Every path outside `/repos/{owner}/{repo}` except `GET /rate_limit` and `GET /meta`. |

The families are a backstop for the table, not a complete list of dangerous endpoints: anything
the table does not list is denied.

### 5.4 GraphQL

Not supported in v0. `POST /api/graphql` returns a GraphQL error response that `gh` prints, telling
the agent to use the REST API through `gh api`, with an example (section 8). Most `gh pr` and
`gh issue` subcommands use GraphQL; agents use `gh api repos/...` instead. `gh run`, `gh release`,
`gh workflow` and `gh api` use REST and work.

### 5.5 ghgw endpoints

- `GET /_ghgw/whoami`: user, groups and effective grants. Used by `setup`, `doctor` and error
  messages.

## 6. Policy

- Deny by default. Effective grants = the user's own grants plus those of all its groups.
- No deny rules: only the union of grants plus the hard rules, so every decision has one readable
  reason ("allowed by grant 2 of group agents"). The number is the grant's ID, unique across the
  policy, so the admin can find and remove it; when several grants allow a request, the lowest ID
  is cited. IDs are assigned when a grant is created and never reused, so an old audit record never
  names a newer grant.
- A grant has at most 100 repository patterns and 100 push patterns.
- Repository patterns are `owner/name` globs (`bolaum/*`, `acme/app`). The owner is literal, so a
  grant never reaches an owner the admin did not name. In the name, `*` matches any run of
  characters (`acme/agent-*`); `**` is rejected, and so is a name ending in `.git`. Owners and
  names match case-insensitively, like GitHub.
- Branch globs (`push`) match branch names without `refs/heads/` and support a subset of GitHub's
  branch filter patterns, with the same meaning: literals, `*` (any run of characters except `/`)
  and `**` (any run, `/` included); `agent/**` matches `agent/x` and `agent/x/y`, not `agent`.
  GitHub's other special characters (`?`, `+`, `[`, a leading `!`) are rejected rather than taken
  literally. Globs are case-sensitive, like git refs. A glob must admit a valid branch name: with
  each run of stars replaced by one letter it must pass `git check-ref-format` (`a.*.b` passes,
  `*.lock` and `.*` are rejected). A glob is at most 1013 bytes, the longest a branch name can be
  within the 1024-byte ref limit. A glob cannot start with `refs/`: that is almost always a full
  ref name written by mistake (`refs/heads/agent/*`). A branch literally named `refs/...` can only
  be matched by a wildcard such as `**`.
- `access` governs git and `api` governs REST, independently: a review agent can have
  `access: read` and `api: pr`. `push` globs require `access: write`.
- User and group names are lowercase (`[a-z0-9][a-z0-9._-]*`, up to 64 characters). A disabled user
  is denied everything.

```yaml
groups:
  agents:
    grants:
      - repos: ["bolaum/*"]
        access: write        # read | write
        push: ["agent/**"]   # branch globs; empty = no push
        api: pr              # read | pr; omitted = no REST

users:
  rpi01-agent:
    groups: [agents]
  devct01-agent:
    groups: [agents]
    grants:
      - repos: ["acme/ml-lab"]
        access: write
        push: ["agent/**"]
        api: pr
```

A request is allowed when some effective grant matches the repository and allows the operation,
the owner has a credential, and no hard rule denies it. Checks run from the most fundamental to the
most specific, and the reason is the first one that fails, so it names the first thing to change:
the user (unknown, disabled), access to the repository, the hard rules and the grants for the
operation, then the owner's credential. `ghgw explain` shows the decision and its reason without
making the request; for a push it also shows the decision on each ref.

## 7. Credentials

- One credential per owner. v0: fine-grained PAT; the admin should limit it to the repositories
  agents may use.
- Added from stdin or a file (never as a command-line argument), verified with an API call.
- A token is 1 to 1024 visible ASCII characters (no spaces or line breaks: it goes into an HTTP
  header).
- Encrypted at rest with AES-256-GCM under a master key generated on first start (state directory,
  mode 0600) or given through `GHGW_MASTER_KEY`. The key is 32 random bytes in standard base64,
  the same in the file and in the variable. Each encryption has a random nonce, and the owner
  (lowercased) is authenticated with the ciphertext, so a credential copied to another owner fails
  to decrypt instead of being sent for the wrong owner.
- The database holds a value sealed under the master key, so a wrong key stops `ghgw serve` at
  start with a clear error. A missing key file stops it too once the database exists: a new key
  would only lock the existing credentials away. So does a database with credentials but no such
  value. ghgw never replaces an existing key file.
- The token expiry GitHub returns in the `github-authentication-token-expiration` response header
  is stored; ghgw warns in the log, in `ghgw owner list` and in `doctor` before it expires.
- Later: GitHub App credentials (installation tokens minted per request, scoped to the repository).

## 8. Errors guide the next step

Every denial says what was denied, why, and what would work. The agent reads the message and
adjusts; no agent-side rules are needed. Lists in messages (allowed repositories, branches, grants)
are at most 1 KiB as rendered, "and N more" included: the first item is always shown, cut if
needed, and the items that do not fit are counted.

```
! [remote rejected] main -> main (ghgw: push to the default branch is not allowed; allowed branches: agent/**)
```

```
ghgw: GraphQL is not supported yet. Use the REST API through `gh api`, e.g.
gh api repos/{owner}/{repo}/pulls -f title=... -f head=... -f base=...
```

```
ghgw: rpi01-agent cannot access acme/secret. Repositories allowed: bolaum/*, acme/ml-lab
```

## 9. Admin

v0 ships only the local admin commands of milestone M3; the admin API, the admin client and the
full CLI below are v1 (section 17).

### 9.1 Admin API

JSON over HTTPS on the admin listener, `/admin/v1/...`, authenticated with an admin token (`ghgwa_`
and 64 lowercase hex characters, stored hashed like user keys). On first start (no admin token in
the database) `ghgw serve` creates one, writes it to `admin-token` in the state directory (mode
0600), stores its hash and prints the file's path, never the token: stdout ends up in logs. If
`admin-token` already exists then (left by an interrupted first start or an earlier database), it
refuses to start rather than revive a token that may have been shared: the admin removes the file.
All admin clients (CLI now; MCP server and web UI later) use `pkg/adminclient`.

Resources (JSON; lists are paginated with `?cursor=`; errors are `{"error": {"code", "message"}}`):

```
GET|POST          /admin/v1/users                 GET|PATCH|DELETE /admin/v1/users/{name}
POST              /admin/v1/users/{name}/rotate-key
GET|POST          /admin/v1/groups                GET|DELETE       /admin/v1/groups/{name}
PUT|DELETE        /admin/v1/groups/{name}/members/{user}
GET|POST          /admin/v1/grants                DELETE           /admin/v1/grants/{id}
GET|POST          /admin/v1/owners                GET|PUT|DELETE   /admin/v1/owners/{owner}
GET|PUT           /admin/v1/policy                (the whole policy; PUT ?dry_run=true returns the diff)
POST              /admin/v1/explain               {user, repo, operation} → {allowed, reason, grant}
GET               /admin/v1/audit                 ?user=&repo=&since=&until=&decision=
```

Every mutating route accepts `?dry_run=true` and then returns the change it would make.

### 9.2 CLI

```
ghgw serve                                  run the gateway and admin listeners
ghgw login | logout                         save/remove the admin URL and token
ghgw user create|list|show|disable|delete|rotate-key
ghgw group create|list|delete|add-user|remove-user
ghgw grant add|remove (--user U | --group G)
ghgw owner add|list|rotate|remove           credentials (token from stdin or --token-file)
ghgw policy export | apply -f FILE          declarative: the whole policy as YAML
ghgw explain --user U --repo O/R --op OP    decision and reason, without a request
ghgw audit [--user U] [--repo O/R] [--since 1h] [--follow]
ghgw setup | credential | doctor | whoami   client side (section 10)
ghgw version
```

CLI rules, so people and LLMs can both drive it:

- Readable output by default (lipgloss tables and colors); `--json` everywhere, stable.
- `--dry-run` on every change, showing the diff; `policy apply` shows the diff before applying.
- Interactive prompts (huh) only with a TTY; without one, everything comes from flags and nothing
  waits for input.
- `--help` with examples; consistent exit codes.
- A new key is printed once, or written to `--key-file` (mode 0600) so it never has to pass
  through an LLM's context.

### 9.3 Later

- `ghgw mcp`: an MCP server over stdio on the admin side, a thin layer over `pkg/adminclient`, for
  admin from clients without a shell. Never for the agents being governed.
- A web UI embedded in the binary, on the admin listener.

## 10. Client side

```
GHGW_URL=https://ghgw.example GHGW_TOKEN=ghgw_... ghgw setup            # this repository
GHGW_URL=https://ghgw.example GHGW_TOKEN=ghgw_... ghgw setup --global   # the user's account
ghgw setup --undo [--global]
```

`setup`:

1. checks the key with `/_ghgw/whoami` and shows the user and its grants;
2. saves the URL and key in `$XDG_CONFIG_HOME/ghgw/config.yaml` (mode 0600); the variables are
   only needed the first time;
3. sets `url.<gateway>/.insteadOf` for `https://github.com/`, `git@github.com:` and
   `ssh://git@github.com/` (`git config --local`, or `--global`);
4. sets `ghgw credential` as git's credential helper for the gateway URL;
5. logs `gh` in for the gateway host (`gh auth login --hostname <host> --with-token`), if `gh` is
   installed;
6. prints what changed.

`gh` then picks the gateway as its host from the rewritten remote URLs. Outside a repository,
`GH_HOST=<gateway host>` does the same.

`ghgw credential` implements git's credential helper protocol and returns the saved key.
`ghgw doctor` checks that git and gh really go through the gateway, the key works and the
certificate is trusted.

## 11. Audit

One record per request: time, user, owner/repo, operation (or git service and refs), decision,
reason, upstream status, duration. Stored in SQLite (retention configurable, default 90 days) and
logged with `slog` to stdout. Secrets are never logged.

## 12. Server configuration

- Config file (YAML) plus `GHGW_*` environment overrides: listen addresses, TLS, state directory,
  retention.
- State directory: `$XDG_STATE_HOME/ghgw/` of the service user: `ghgw.db` (SQLite, with its
  `-wal` and `-shm` files), `master.key` and `admin-token`. ghgw creates the directory with mode
  0700 and the files with mode 0600 from the start, and never replaces an existing file; a file left
  partial by an interrupted first start is reported as malformed, with what to do. It refuses to
  start when the directory or one of these files is a symbolic link, is owned by another user, or
  gives any permission to group or others; the error names the `chmod` to run. Only the directory
  itself is checked, not its parents.
- Dynamic state (users, groups, grants, owners) lives in SQLite and changes through the admin API.

## 13. TLS

- v0: certificate and key files (reloaded when they change), or `--self-signed` for development.
- Production needs a certificate the clients trust; `gh` uses the system roots. A DNS-01 ACME
  certificate is the easy path for a gateway that is not publicly reachable.

## 14. Distribution and tests

- goreleaser: binaries for linux/amd64 and linux/arm64 (darwin later), a container image, an
  example systemd unit.
- Tests: `core` unit tests (table-driven, policy and operation classification), gateway tests
  against a fake GitHub with recorded fixtures, an optional end-to-end test against a real test
  repository with a PAT from the environment.

## 15. Implementation choices

- Dependencies: `spf13/cobra` (commands), `charmbracelet/lipgloss` and `charmbracelet/huh` (CLI
  output and prompts), `modernc.org/sqlite` (store), `gopkg.in/yaml.v3` (config and policy files).
  Anything else needs a reason in the PR.
- git protocol: pkt-line parsing and receive-pack reports are written by hand in
  `internal/gateway`; no go-git in v0.
- HTTP: `net/http` and `httputil.ReverseProxy` with streaming bodies; no web framework.
- Logging: `log/slog`, JSON in production, text on a TTY.
- Upstream base URLs (`https://github.com`, `https://api.github.com`) are configurable so tests can
  point them at a fake GitHub (`httptest`).
- SQLite migrations are embedded SQL files (`NNNN_name.sql`, numbered from 1 without gaps) applied
  in order at startup, in one transaction; `PRAGMA user_version` records how many are applied, and
  a database from a newer ghgw, or with a negative version, is refused.

## 16. v0 milestones

v0 is done when the coding agents that develop ghgw work through ghgw: no GitHub credential in
their containers. Anything that use does not need waits for v1 (section 17). Each milestone is one
pull request; "done" means the listed checks pass in CI.

| # | Scope | Done when |
|---|---|---|
| M0 | Module, cobra root, `ghgw version`, Makefile, CI | Done |
| M1 | `internal/core`: users, groups, grants, hard rules, `Decide`, explain | Done |
| M2 | `internal/store` (SQLite, migrations), owners with sealed credentials, master key, keys and tokens | Store tests; credentials are unreadable in the database file |
| M3 | Local admin, no admin API: the policy (users with key hashes, groups, grants) in a YAML file read by `ghgw serve`; `ghgw key new` (shows a key once, prints its hash for the file); `ghgw owner add\|list\|remove` on the local store (token from stdin or a file); `ghgw explain` against the file (`--default-branch` for pushes) | A script writes the policy of section 6, adds an owner, and `explain` answers as expected |
| M4 | Gateway listener, authentication, git fetch/clone proxy | `git clone` through the gateway works against a fake upstream; unknown keys and repos get the section 8 messages |
| M5 | Push checks and receive-pack reports | Push to an allowed branch passes; default branch, tags and other branches are rejected with clear `ng` lines; nothing reaches the upstream on rejection |
| M6 | `docs/operations.md`: the REST operation table, only what an agent needs to work on pull requests through `gh api` | Approved by the maintainer |
| M7 | REST proxy with that table: classification, hard rules, `Link`/`Location` rewrite, GraphQL guidance | `gh api` creates and comments on a pull request against the fake upstream; denied operations return guidance |
| M8 | Client side, minimal: `ghgw setup --global` (git `insteadOf`, credential helper, the gh host), `ghgw credential`, `ghgw whoami` | In a scratch repository, one `ghgw setup` makes `git push` and `gh api` go through the gateway |
| M9 | Running it: one request log line per request (`slog`, stdout), TLS from certificate and key files, an example systemd unit | The agents developing ghgw work through a deployed gateway with no PAT in their containers |

## 17. Roadmap

- **v0**: section 16.
- **v1**: the admin API, `pkg/adminclient` and the full CLI of section 9; audit in the store with
  retention and `ghgw audit`; presets beyond the v0 table (labels with per-grant allowlists,
  reviewers, re-runs, `gh run`); `setup --undo` and `doctor`; `--self-signed`; GraphQL (operation
  allowlist, node ID → owner mapping); `no_force` on grants (ancestry from the pack); GitHub App
  credentials; per-user rate limits; goreleaser builds and a container image.
- **Later**: MCP admin server, web UI, GitHub Enterprise upstreams, darwin builds.

## 18. Open questions

- Which credential `GET /rate_limit` uses: the path names no owner (milestone M7).
- Whether agents get a read-only view of their own access beyond `whoami`.
