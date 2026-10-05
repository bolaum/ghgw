# REST operations

Status: approved (milestone M6), with the maintainer's answers to the open questions (section 8).
M7 implements the tables below as the operation table of `internal/core` (`operations.go`), with
the tests of section 5.4; change both together.

This document proposes the REST operations of the `read` and `pr` presets (SPEC.md section 5.3).
The table is the allow-list: anything it does not list is denied. v0 lists only what the agents
developing ghgw need to work on pull requests through `gh api` (SPEC.md section 16); what other
uses would need waits for v1 (section 7).

## 1. Conventions

- Names, methods, path templates and documentation links come from GitHub's OpenAPI description
  of api.github.com ([github/rest-api-description](https://github.com/github/rest-api-description),
  fetched 2026-10-05). A name is GitHub's `operationId` with `/` replaced by `.` (`pulls/create`
  becomes `pulls.create`), so every name can be looked up in GitHub's description.
- Every entry passes `NewRESTTable` with its class: canonical path template, `GET` for `read`, and
  no hard-rule family reachable.
- ghgw classifies a request by method and path (section 5.1). Bodies and query strings are not
  read, with two exceptions: the bodies of `pulls.create` and `pulls.create-review` (section 5.2).
  Every other entry is judged on the worst body GitHub accepts for it.
- Every request runs with the owner's credential, so on GitHub every write is authored by the
  user who owns the PAT, whichever agent made it. Only ghgw's request log tells which agent it was.
- Every grant has git access, at least `read`. The REST reads therefore expose no code of the
  granted repositories beyond what a clone gives; what they add is the collaboration data (issues,
  pull requests, comments) and CI. No entry takes code from another repository: a pull request's
  source must be a branch of the repository itself (section 5.2).
- One limit is GitHub's: the repositories of a fork network share their git objects, and GitHub
  serves a commit of any of them through each of them, given its SHA
  ([docs](https://docs.github.com/pull-requests/reference/forks)). ghgw cannot tell which
  repository a SHA came from, so a grant on a repository also reaches, by SHA, the commits of its
  forks, private ones included. The admin should not grant a repository whose fork network holds
  forks an agent may not read (SPEC.md section 6).

## 2. Workflows

What an agent does with the presets, all through `gh api` (no GraphQL in v0, and no `gh run`,
section 7). `gh api` fills in `{owner}` and `{repo}` from the repository in the current directory.
The comment on each line is the operation the gateway classifies the request as. Numbers (pull
request 42, run 1234, ...) are examples.

### 2.1 Read a repository and its files (`read`)

```sh
gh api repos/{owner}/{repo} --jq .default_branch                          # repos.get
gh api repos/{owner}/{repo}/contents/docs --jq '.[].path'                 # repos.get-content
gh api 'repos/{owner}/{repo}/contents/go.mod?ref=agent/fix-42' \
  -H 'Accept: application/vnd.github.raw+json'                             # repos.get-content
```

Agents normally work in a clone; the contents API is for a file at another ref without fetching
it.

### 2.2 Commits and branches (`read`)

```sh
gh api 'repos/{owner}/{repo}/branches?per_page=100' --paginate --jq '.[].name'  # repos.list-branches
gh api repos/{owner}/{repo}/branches/agent/fix-42 --jq .commit.sha        # repos.get-branch
gh api 'repos/{owner}/{repo}/commits?sha=main&path=internal/core'         # repos.list-commits
gh api repos/{owner}/{repo}/commits/3f2a9c1 \
  -H 'Accept: application/vnd.github.diff'                                 # repos.get-commit
```

### 2.3 Pull requests, reviews and comments (`read`)

```sh
gh api 'repos/{owner}/{repo}/pulls?state=open&head={owner}:agent/fix-42'  # pulls.list
gh api repos/{owner}/{repo}/pulls/42 --jq '[.state, .base.ref, .head.ref]'  # pulls.get
gh api repos/{owner}/{repo}/pulls/42 -H 'Accept: application/vnd.github.diff'  # pulls.get
gh api repos/{owner}/{repo}/pulls/42/commits --jq '.[].sha'              # pulls.list-commits
gh api repos/{owner}/{repo}/pulls/42/files --paginate                    # pulls.list-files
gh api repos/{owner}/{repo}/pulls/42/reviews                             # pulls.list-reviews
gh api repos/{owner}/{repo}/pulls/42/reviews/2211                        # pulls.get-review
gh api repos/{owner}/{repo}/pulls/42/comments --paginate                 # pulls.list-review-comments
gh api repos/{owner}/{repo}/pulls/comments/1873                          # pulls.get-review-comment
gh api repos/{owner}/{repo}/issues/42/comments --paginate                # issues.list-comments
gh api repos/{owner}/{repo}/issues/comments/9921                         # issues.get-comment
```

A pull request is also an issue with the same number: its conversation (the comments that are not
on a line) is read and written through the issues API.

### 2.4 Issues (`read`)

```sh
gh api 'repos/{owner}/{repo}/issues?state=open&labels=bug' --paginate    # issues.list-for-repo
gh api repos/{owner}/{repo}/issues/17                                    # issues.get
gh api repos/{owner}/{repo}/issues/17/comments                           # issues.list-comments
```

### 2.5 CI (`read`)

```sh
sha=$(git rev-parse HEAD)
gh api repos/{owner}/{repo}/commits/$sha/check-runs \
  --jq '.check_runs[] | [.name, .status, .conclusion] | @tsv'             # checks.list-for-ref
gh api repos/{owner}/{repo}/commits/$sha/status --jq .state              # repos.get-combined-status-for-ref
gh api "repos/{owner}/{repo}/actions/runs?head_sha=$sha" \
  --jq '.workflow_runs[] | [.id, .name, .conclusion] | @tsv'              # actions.list-workflow-runs-for-repo
gh api repos/{owner}/{repo}/actions/runs/1234/jobs \
  --jq '.jobs[] | select(.conclusion == "failure") | [.id, .name] | @tsv'  # actions.list-jobs-for-workflow-run
gh api repos/{owner}/{repo}/actions/jobs/5678/logs                       # actions.download-job-logs-for-workflow-run
```

GitHub answers the log request with a redirect to a signed URL on a storage host. The gateway
follows it and streams the log, so agents only ever reach the gateway (section 5.3).

### 2.6 Open, update and comment on a pull request (`pr`)

```sh
git push origin agent/fix-42                                             # git, through the push checks
gh api -X POST repos/{owner}/{repo}/pulls -f head=agent/fix-42 -f base=main \
  -f title='core: fix the glob cut' -F body=@pr.md                       # pulls.create
gh api -X PATCH repos/{owner}/{repo}/pulls/42 -F body=@pr.md             # pulls.update
gh api -X PATCH repos/{owner}/{repo}/pulls/42 -f state=closed            # pulls.update
gh api -X POST repos/{owner}/{repo}/issues/42/comments \
  -f body='Rebased on main; CI is green.'                                # issues.create-comment
gh api -X POST repos/{owner}/{repo}/issues/17/comments -F body=@note.md  # issues.create-comment
```

`head` is a branch of the same repository: the gateway denies a source in another repository,
`owner:branch` or `head_repo` (section 5.2).

Marking a draft pull request ready for review is GraphQL only, so an agent that opens a draft
leaves that step to a person.

### 2.7 Review a pull request and reply to review comments (`pr`)

```sh
gh api -X POST repos/{owner}/{repo}/pulls/42/comments/1873/replies \
  -f body='Done in 3f2a9c1.'                                             # pulls.create-reply-for-review-comment
gh api -X POST repos/{owner}/{repo}/pulls/42/reviews --input review.json # pulls.create-review
```

```json
{
  "event": "COMMENT",
  "body": "Two problems, see the line comments.",
  "comments": [
    {"path": "internal/core/glob.go", "line": 42, "side": "RIGHT", "body": "This cuts inside an escape."}
  ]
}
```

`event` must be `COMMENT`: the gateway denies approvals, change requests and pending reviews
(section 5.2).

### 2.8 Re-run failed jobs (`pr`)

```sh
gh api -X POST repos/{owner}/{repo}/actions/runs/1234/rerun-failed-jobs # actions.re-run-workflow-failed-jobs
gh api repos/{owner}/{repo}/actions/runs/1234 --jq '[.status, .conclusion]'  # actions.get-workflow-run
```

## 3. The `read` preset

Every entry is a `GET` on one repository of the grant.

| Name | Method | Path | Rationale | Docs |
|---|---|---|---|---|
| `repos.get` | GET | `/repos/{owner}/{repo}` | Default branch, visibility and the credential's permissions: where every workflow starts. | [docs](https://docs.github.com/rest/repos/repos#get-a-repository) |
| `repos.get-content` | GET | `/repos/{owner}/{repo}/contents/{path}` | A file or a directory at any ref, without fetching it. | [docs](https://docs.github.com/rest/repos/contents#get-repository-content) |
| `repos.list-branches` | GET | `/repos/{owner}/{repo}/branches` | Which branches exist, e.g. whether the agent's branch is there. | [docs](https://docs.github.com/rest/branches/branches#list-branches) |
| `repos.get-branch` | GET | `/repos/{owner}/{repo}/branches/{branch}` | The head commit of one branch, to compare with the clone. | [docs](https://docs.github.com/rest/branches/branches#get-a-branch) |
| `repos.list-commits` | GET | `/repos/{owner}/{repo}/commits` | History of a branch or a path. | [docs](https://docs.github.com/rest/commits/commits#list-commits) |
| `repos.get-commit` | GET | `/repos/{owner}/{repo}/commits/{ref}` | One commit and its files; its diff with the diff media type. | [docs](https://docs.github.com/rest/commits/commits#get-a-commit) |
| `pulls.list` | GET | `/repos/{owner}/{repo}/pulls` | Find pull requests, e.g. the open one for the agent's branch (`head=`). | [docs](https://docs.github.com/rest/pulls/pulls#list-pull-requests) |
| `pulls.get` | GET | `/repos/{owner}/{repo}/pulls/{pull_number}` | State, base, head and body of one pull request; its diff with the diff media type. | [docs](https://docs.github.com/rest/pulls/pulls#get-a-pull-request) |
| `pulls.list-commits` | GET | `/repos/{owner}/{repo}/pulls/{pull_number}/commits` | The commits a pull request brings. | [docs](https://docs.github.com/rest/pulls/pulls#list-commits-on-a-pull-request) |
| `pulls.list-files` | GET | `/repos/{owner}/{repo}/pulls/{pull_number}/files` | Changed files and their patches, for a review. | [docs](https://docs.github.com/rest/pulls/pulls#list-pull-requests-files) |
| `pulls.list-reviews` | GET | `/repos/{owner}/{repo}/pulls/{pull_number}/reviews` | Review verdicts and their summaries. | [docs](https://docs.github.com/rest/pulls/reviews#list-reviews-for-a-pull-request) |
| `pulls.get-review` | GET | `/repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}` | One review, as linked by `#pullrequestreview-<id>`. | [docs](https://docs.github.com/rest/pulls/reviews#get-a-review-for-a-pull-request) |
| `pulls.list-review-comments` | GET | `/repos/{owner}/{repo}/pulls/{pull_number}/comments` | Line comments, with the IDs that replies need. | [docs](https://docs.github.com/rest/pulls/comments#list-review-comments-on-a-pull-request) |
| `pulls.get-review-comment` | GET | `/repos/{owner}/{repo}/pulls/comments/{comment_id}` | One line comment, as linked by `#discussion_r<id>`. | [docs](https://docs.github.com/rest/pulls/comments#get-a-review-comment-for-a-pull-request) |
| `issues.list-for-repo` | GET | `/repos/{owner}/{repo}/issues` | Find issues (GitHub lists pull requests here too). | [docs](https://docs.github.com/rest/issues/issues#list-repository-issues) |
| `issues.get` | GET | `/repos/{owner}/{repo}/issues/{issue_number}` | One issue: title, body, labels, state. | [docs](https://docs.github.com/rest/issues/issues#get-an-issue) |
| `issues.list-comments` | GET | `/repos/{owner}/{repo}/issues/{issue_number}/comments` | The conversation of an issue or a pull request. | [docs](https://docs.github.com/rest/issues/comments#list-issue-comments) |
| `issues.get-comment` | GET | `/repos/{owner}/{repo}/issues/comments/{comment_id}` | One comment, as linked by `#issuecomment-<id>`. | [docs](https://docs.github.com/rest/issues/comments#get-an-issue-comment) |
| `checks.list-for-ref` | GET | `/repos/{owner}/{repo}/commits/{ref}/check-runs` | CI results of a commit, from Actions and other apps (see the note below). | [docs](https://docs.github.com/rest/checks/runs#list-check-runs-for-a-git-reference) |
| `repos.get-combined-status-for-ref` | GET | `/repos/{owner}/{repo}/commits/{ref}/status` | CI results reported as commit statuses (older integrations). | [docs](https://docs.github.com/rest/commits/statuses#get-the-combined-status-for-a-specific-reference) |
| `actions.list-workflow-runs-for-repo` | GET | `/repos/{owner}/{repo}/actions/runs` | The runs of a branch or a commit (`branch=`, `head_sha=`). | [docs](https://docs.github.com/rest/actions/workflow-runs#list-workflow-runs-for-a-repository) |
| `actions.get-workflow-run` | GET | `/repos/{owner}/{repo}/actions/runs/{run_id}` | One run's status, e.g. after a re-run. | [docs](https://docs.github.com/rest/actions/workflow-runs#get-a-workflow-run) |
| `actions.list-jobs-for-workflow-run` | GET | `/repos/{owner}/{repo}/actions/runs/{run_id}/jobs` | Which jobs and steps failed. | [docs](https://docs.github.com/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run) |
| `actions.download-job-logs-for-workflow-run` | GET | `/repos/{owner}/{repo}/actions/jobs/{job_id}/logs` | The log of a failed job: what the agent fixes from. | [docs](https://docs.github.com/rest/actions/workflow-jobs#download-job-logs-for-a-workflow-run) |

GitHub's docs require the "Checks" permission for `checks.list-for-ref`, and fine-grained PATs do
not offer it, so with v0 credentials it probably answers on public repositories only. It stays:
it costs nothing, and GitHub App credentials (v1) have that permission.

What `read` exposes beyond a clone: issues, pull requests, comments and CI logs of the granted
repositories. GitHub masks registered secrets in logs, but a workflow can still print something
sensitive that is not registered as a secret; whoever may read CI on GitHub reads the same logs.

## 4. The `pr` preset

`pr` is `read` plus these entries.

| Name | Method | Path | Rationale | Docs |
|---|---|---|---|---|
| `pulls.create` | POST | `/repos/{owner}/{repo}/pulls` | Open a pull request from a pushed branch of the same repository (section 5.2). | [docs](https://docs.github.com/rest/pulls/pulls#create-a-pull-request) |
| `pulls.update` | PATCH | `/repos/{owner}/{repo}/pulls/{pull_number}` | Keep the title and body current; close a pull request the agent gives up on. | [docs](https://docs.github.com/rest/pulls/pulls#update-a-pull-request) |
| `issues.create-comment` | POST | `/repos/{owner}/{repo}/issues/{issue_number}/comments` | Comment on a pull request or an issue (the conversation, not a line). | [docs](https://docs.github.com/rest/issues/comments#create-an-issue-comment) |
| `pulls.create-review` | POST | `/repos/{owner}/{repo}/pulls/{pull_number}/reviews` | Review a pull request: a summary and line comments in one call, `event: COMMENT` only (section 5.2). | [docs](https://docs.github.com/rest/pulls/reviews#create-a-review-for-a-pull-request) |
| `pulls.create-reply-for-review-comment` | POST | `/repos/{owner}/{repo}/pulls/{pull_number}/comments/{comment_id}/replies` | Answer a line comment in its thread. | [docs](https://docs.github.com/rest/pulls/comments#create-a-reply-for-a-review-comment) |
| `actions.re-run-workflow-failed-jobs` | POST | `/repos/{owner}/{repo}/actions/runs/{run_id}/rerun-failed-jobs` | Re-run the failed jobs of a run, e.g. after a flaky failure. | [docs](https://docs.github.com/rest/actions/workflow-runs#re-run-failed-jobs-from-a-workflow-run) |

Besides the presets, the table has the two `global` entries of SPEC.md section 5.3, allowed for
every enabled user and forwarded without a credential, since their path names no owner:
`rate-limit.get` (`GET /rate_limit`) and `meta.get` (`GET /meta`). Without a credential GitHub
reports the gateway's own unauthenticated rate limit, not an owner's.

### 4.1 What limits every `pr` entry

- Only the granted repositories, and every request is in ghgw's request log with the agent's name.
- No `pr` entry changes code, merges, releases, reports a CI result or starts a workflow of its
  own choosing: those are hard rules. No `pr` entry approves, requests changes or adds labels.
  What is left is noise, misleading text, and whatever automation reacts to pull requests and
  comments.
- Everything shows in the repository's timeline and a person can undo it (edit, reopen); only the
  notifications already sent stay.
- GitHub's secondary rate limits on content creation cap spam until ghgw has per-user rate
  limits (v1).
- The table has no edits or deletes of comments and reviews, so an agent cannot rewrite or hide
  what was said (section 6.2).

Two risks are common to several entries and limited by the admin, not by the table:

- **Automation that trusts the credential's user.** Writes are authored by the PAT's user, often
  a maintainer. Bots and workflows that act on a maintainer's comment (`/deploy`, `/merge`,
  `/ok-to-test`) obey an agent just as well, and ghgw does not read comment bodies. The admin
  should not give `pr` on a repository where a comment from that user merges, deploys or runs
  untrusted code.
- **CI runs the agent's code.** A pushed branch, and the pull request opened from it, run the
  repository's workflows on the agent's code, with whatever secrets those workflows expose. This
  comes with push access (M5) more than with `pr`. A PAT without the "Workflows" permission makes
  GitHub reject pushes that change `.github/workflows/`, so an agent cannot write a new workflow;
  the existing ones still run its code. SPEC.md section 7 recommends leaving that permission out.

### 4.2 Abuse, entry by entry

**`pulls.create`**

- Abuse: pull request spam; a pull request from a branch the agent did not write into any base
  branch; turning someone's issue into a pull request (`issue`); a misleading title or body that a
  person merges on trust. A source in another repository (`owner:branch`, `head_repo`), such as a
  private fork the grant does not cover, would expose that repository's changes through the pull
  request's files and diff, which `read` allows.
- Limits: the gateway forwards a pull request only when its source is a branch of the repository
  itself, checked in the body before anything reaches GitHub (section 5.2); sources in other
  repositories wait for v1 (section 7). Opening a pull request merges nothing, and merging is a
  hard rule. Code in a branch of the repository got there through the push checks or a person.
  The `pull_request` workflows it triggers run the same code that the push already ran in most
  repositories (4.1). Acceptable.

**`pulls.update`**

- Abuse: edit the title and body of any pull request, people's included; close any pull request;
  change its base branch; turn `maintainer_can_modify` off on a fork's pull request.
- Limits: the body takes no source, so the head stays the branch the pull request was opened
  from. The timeline records title and base changes and closes, GitHub keeps the edit history
  of the body, and a person reverts or reopens. Restricting it to the agent's own pull requests is
  not possible by path, nor by author: agents and the owner share one GitHub user. Acceptable.

**`issues.create-comment`**

- Abuse: comment spam and `@mention` spam; text that reads as the owner's own words; commands to
  bots and `issue_comment` workflows (4.1).
- Limits: the agent cannot edit or delete comments afterwards; people can. Command automation is
  the admin's to know (4.1). Acceptable with that guidance.

**`pulls.create-review`**

- Abuse: `APPROVE` counts toward required reviews, and toward code owner reviews when the PAT's
  user is a code owner, so a prompt-injected agent could approve someone else's malicious pull
  request and a person merge it on trust. `REQUEST_CHANGES` can block a merge until someone
  dismisses it. Line comment spam.
- Limits: the gateway forwards a review only when its body says `event: COMMENT`, checked before
  anything reaches GitHub (section 5.2); approvals, change requests and pending reviews are denied.
  What is left is a comment with line comments attached. Acceptable.

**`pulls.create-reply-for-review-comment`**

- Abuse: reply spam; replying "fixed" without fixing.
- Limits: as for comments. Resolving a thread is GraphQL only, so the reviewer still sees every
  thread open and checks the answer. Acceptable.

**`actions.re-run-workflow-failed-jobs`**

- Abuse: re-run the failed jobs of any run, deploy and release jobs included, with the jobs that
  depend on them; burn Actions minutes by re-running in a loop; `enable_debug_logging` makes the
  runner log more.
- Limits: a re-run uses the original run's commit, ref and workflow files, and the privileges of
  the actor who triggered the run, not those of the one who re-runs it
  ([docs](https://docs.github.com/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs)):
  it runs no new code and gains nothing. Only runs from the last 30 days can be re-run. Debug logs
  still mask secrets. Acceptable.

## 5. Requirements for M7

What the tables cannot say on their own: how a request finds its entry, the two bodies ghgw
reads, and redirects. SPEC.md section 5.3 states the rules; this section gives the reasons and the
tests.

### 5.1 Matching a request to an entry

- **Canonical path.** The gateway decodes the request path once and matches the decoded
  segments. A segment that is empty, `.` or `..`, or that still contains `%`, `\` or a control
  character after decoding, makes the request invalid. The gateway forwards the matched path with
  each segment escaped again, so GitHub sees the segments ghgw classified: `branches/agent%2Ffix`
  is forwarded as `branches/agent/fix`, and `branches/main%2Fprotection` is
  `branches/main/protection`, which the families deny.
- **Numbers.** A parameter GitHub types as an integer matches ASCII digits only. In this table
  that is `{pull_number}`, `{issue_number}`, `{review_id}`, `{comment_id}`, `{run_id}` and
  `{job_id}`. Without that, `pulls/{pull_number}` and `issues/{issue_number}` would also match
  `pulls/comments`, `issues/comments` and `issues/events`, repository-wide lists that are left
  out (6.3). Preferring literal routes does not help: those lists are not in the table to prefer.
- **Parameters that span segments.** Branch names and file paths contain `/`, so two parameters
  match one or more segments: `{path}` in `contents/{path}` and `{branch}` in
  `branches/{branch}`. `GET contents` (the root directory) is `repos.get-content` too. A
  parameter may span only when it ends a `read` template and every `GET` route GitHub has below
  it is in a hard-rule family, so that a longer value cannot name an operation the table leaves
  out: there is none below `contents/{path}`, and only branch protection (Administration) below
  `branches/{branch}`. Every other parameter matches one segment.
- **Commit refs.** `{ref}` in `commits/{ref}` matches one segment. GitHub has five reads below it
  that are left out (6.3): `commits/{ref}/comments`, `pulls`, `branches-where-head`,
  `check-suites` and `statuses`. A spanning `{ref}` would admit them as `repos.get-commit` of a
  ref named `3f2a9c1/comments`, and literal precedence cannot help, since they are not in the
  table. Agents pass a SHA (`git rev-parse`), as in sections 2.2 and 2.5, or a branch name
  without `/`.
- **Precedence.** When several templates match, the first position where they differ decides:
  a literal beats a parameter. In this table numbers and single segments already keep the
  templates apart, so the rule only settles later entries.
- **Families.** `NewRESTTable` keeps treating every parameter as any one segment, which covers
  the numbers. Longer values of a spanning parameter can reach a family
  (`branches/agent/x/protection`); the gateway checks the families on the concrete path of every
  request, before the table, so those requests are denied by the hard rule.

### 5.2 The bodies of `pulls.create` and `pulls.create-review`

The two bodies ghgw reads, because the path cannot tell a comment from an approval, nor a branch
of the repository from a branch of another one. The gateway forwards these requests only when all
of these hold, and denies them otherwise, before anything reaches GitHub:

- no query string (GitHub may take body parameters from it);
- the body is at most 1 MiB (a review with dozens of line comments is a few KiB) and is read
  whole before forwarding;
- it is valid UTF-8 and exactly one JSON object, with nothing after it;
- no two top-level keys are equal once JSON escapes are decoded and case is ignored (`event` and
  `Event`, `head` and `he\u0061d`);
- the condition of the entry:
  - `pulls.create-review`: `event` is present and is the string `COMMENT`.
  - `pulls.create`: every top-level key is one of `title`, `body`, `head`, `base`, `draft`,
    `maintainer_can_modify` and `issue`, so `head_repo` is denied; `head` is present and is a
    string without `:`, so `owner:branch` is denied. Git branch names cannot contain `:`, so this
    denies no branch of the repository.

The forwarded body is the bytes that were checked. The denial says what ghgw allows and shows the
body of section 2.6 or 2.7. A source in another repository would need a decision of its own on
that repository; v0 leaves it out (section 7).

### 5.3 Redirects

- The gateway never follows a redirect from the API, with one exception below. A `Location` on
  api.github.com is rewritten to the gateway (SPEC.md section 5.3), so the agent's next request
  goes through the gateway and gets its own decision and credential. That holds when the target
  is another owner or repository; GitHub's redirect for a renamed repository
  (`/repositories/{id}/...`) is not repository-scoped by name and is denied, with guidance to use
  the new name.
- Pagination links are different: GitHub writes them with the repository's ID
  (`<https://api.github.com/repositories/1296269/pulls?page=2>; rel="next"`), so a `Link` that
  only changed host would make every second page a denied `/repositories/{id}` request. In a
  `Link`, the gateway replaces `/repositories/{id}` with the `/repos/{owner}/{repo}` of the request
  it answers: the page is of the same list, and its request gets a decision on that repository
  anyway.
- The exception is `actions.download-job-logs-for-workflow-run`: the gateway follows its redirect
  itself and streams the log to the agent, which never gets the signed URL. It follows one hop,
  only to an `https` URL, with a new request that carries neither the owner's credential nor any
  header of the agent's request. A Go `http.Client` that follows redirects keeps `Authorization`
  for subdomains, changed ports and `http` on the same host, so M7 does not use one for this.

### 5.4 Tests

M7's tests cover, against the fake GitHub:

- `GET` `pulls/comments`, `issues/comments` and `issues/events`: denied as unknown operations,
  and no request reaches the upstream.
- `pulls.create-review` with `APPROVE`, `REQUEST_CHANGES`, no `event`, `event` that is not a
  string, two `event` keys (equal or conflicting), `Event` next to `event`, `event` in the query
  string, invalid JSON, trailing data and a body over 1 MiB: denied, and no request reaches the
  upstream. A `COMMENT` review is forwarded byte for byte.
- `pulls.create` with a granted destination and a source in a private fork the agent has no grant
  on (`"head": "o:main", "head_repo": "o/secret"`), and with `head` `o:main`, `o/secret:main` or
  `agent:fix`, `head_repo` alone (even naming the same repository), `Head_Repo`, `he\u0061d_repo`,
  an unknown key, two `head` keys (equal or conflicting), `Head` next to `head`, no `head`, `head`
  that is not a string, `head_repo` in the query string, invalid JSON, trailing data and a body
  over 1 MiB: denied, and no request reaches the upstream. `{"head": "agent/fix-42", "base":
  "main", "title": "..."}` is forwarded byte for byte with `api: pr`, and denied with `api: read`.
- `branches/main/protection`, `branches/agent/x/protection`, `branches/main%2Fprotection` and
  `branches/main%252Fprotection`: denied, and no request reaches the upstream.
  `branches/agent/fix-42` and `branches/agent%2Ffix-42` are `repos.get-branch` of `agent/fix-42`.
- `commits/3f2a9c1/` followed by `comments`, `pulls`, `branches-where-head`, `check-suites` or
  `statuses`, and the same five with `3f2a9c1%2F`: denied as unknown operations, and no request
  reaches the upstream. `commits/agent/fix-42` and `commits/agent%2Ffix-42`: denied.
  `commits/3f2a9c1`, `commits/main`, `commits/3f2a9c1/check-runs` and `commits/3f2a9c1/status`
  are `repos.get-commit`, `repos.get-commit`, `checks.list-for-ref` and
  `repos.get-combined-status-for-ref`.
- `contents`, `contents/internal/core/rest.go`, and paths with empty, `.` and `..` segments.
- A `Location` to another owner's repository: rewritten, and the agent's next request is decided
  on that repository and uses that owner's credential. `/repositories/{id}`: denied.
- Job logs: the log is streamed; the storage request carries no `Authorization` and no header of
  the agent's request; a redirect to `http`, or a second redirect, fails the request.
- `issues.add-labels` and `issues.create`: denied (section 7).

## 6. Left out

Every repository operation in GitHub's description (531 on the date above) is in the tables of
sections 3 and 4, in a hard-rule family (6.1), in v1 (section 7), or in one of the groups below.
Whatever is not in the tables is denied, whichever group it is in.

### 6.1 Hard rules

The families of SPEC.md section 5.3, as implemented in `internal/core/rest.go`. These are always
denied, whatever a grant says.

| Hard rule | GitHub operations it covers | Why |
|---|---|---|
| Code change | `repos.create-or-update-file-contents`, `repos.delete-file`, `git.create-blob`, `git.create-tree`, `git.create-commit`, `git.create-tag`, `git.create-ref`, `git.update-ref`, `git.delete-ref`, `repos.merge`, `repos.merge-upstream`, `pulls.update-branch`, `code-scanning.commit-autofix`, the source import writes (`migrations.*`, deprecated) | Every code change goes through the push checks, in one place. The autofix commits to a branch; a source import rewrites the repository. |
| Merge | `pulls.merge`, `pulls.merge-async` | A person merges. `pulls.merge-async` merges a pull request (a whole stack for stacked pull requests) or adds it to the merge queue. |
| Release | `repos.create-release`, `repos.update-release`, `repos.delete-release`, `repos.generate-release-notes`, the release asset writes, reactions on releases | A release creates a tag, and tags cannot be pushed. |
| CI result | `repos.create-commit-status`, `checks.create`, `checks.update`, `checks.rerequest-run`, `checks.create-suite`, `checks.rerequest-suite`, `checks.set-suites-preferences`, `repos.create-attestation`, `code-scanning.upload-sarif`, `dependency-graph.create-repository-snapshot` | An agent could forge results, build provenance, code scanning results and dependency submissions. Re-requesting checks of other CI apps falls here too; Actions re-runs do not. |
| Trigger | `repos.create-dispatch-event`, `actions.create-workflow-dispatch`, `repos.create-deployment`, `repos.create-deployment-status`, `repos.delete-deployment`, `actions.approve-workflow-run`, `actions.review-pending-deployments-for-run`, `actions.review-custom-gates-for-run`, `codespaces.create-with-repo-for-authenticated-user`, `codespaces.create-with-pr-for-authenticated-user` | They run with the repository's secrets: a workflow, a fork's run once approved, a deployment, a codespace with the Codespaces secrets. |
| Administration | 231 operations: `repos.update`, `repos.delete`, `repos.transfer`, `repos.create-fork`, topics, branch rename and protection, collaborators, invitations, hooks, deploy keys, environments, rulesets, Pages, autolinks, interaction limits, immutable releases, custom properties, security toggles and settings, Actions permissions, policies, runners, OIDC and caches, enabling and disabling workflows, secrets and variables (agent ones included), alert and advisory writes, every secret scanning operation | Not an agent's job, and much of it would lift the limits ghgw relies on. Secret scanning alerts carry the detected secret in clear text unless `hide_secret=true`, so their reads are excluded too. |
| Not repository-scoped | `/user`, `/orgs`, `/search`, `/gists`, `/notifications`, `/markdown`, ...; only `GET /rate_limit` and `GET /meta` are `global` | ghgw picks the credential and checks the grant by repository. |

The families also err the other way, which costs nothing here: `PATCH` and `DELETE`
`pulls/comments/{comment_id}` (`pulls.update-review-comment`, `pulls.delete-review-comment`) can
reach `pulls/{n}/update-branch`, `pulls/{n}/merge` and the other `pulls/{n}/...` family paths
through their parameter, so `NewRESTTable` would only accept them with a hard-rule class. They are
left out anyway (6.2).

### 6.2 Writes left out by choice

| Group | Operations | Why |
|---|---|---|
| Editing or deleting what was said | `issues.update-comment`, `issues.delete-comment`, `pulls.update-review-comment`, `pulls.delete-review-comment`, `pulls.update-review`, `pulls.submit-review`, `pulls.delete-pending-review`, `pulls.dismiss-review`, commit comment writes | With write access the credential can edit anyone's comment, and agents share a GitHub user with the owner: an agent could rewrite a person's words or hide its own. Dismissing removes a person's review. |
| Redundant writes | `pulls.create-review-comment` | `pulls.create-review` and `pulls.create-reply-for-review-comment` cover line comments. |
| Issue state and triage | `issues.update` (pull requests have `pulls.update`), `issues.lock`, `issues.unlock`, `issues.set-labels`, `issues.remove-label`, `issues.remove-all-labels`, label creation, update and deletion, assignees, milestones, sub-issues, dependencies and related issues, issue fields and suggestions, comment pins | Triage belongs to people. Closing other people's issues, removing labels and repository-wide label changes stay out. |
| Pull request stacks | `pull-request-stacks.create`, `pull-request-stacks.add`, `pull-request-stacks.unstack` | Not needed; stacks are merged with `pulls.merge-async`. |
| Reactions | every `reactions.create-*` and `reactions.delete-*` | Not needed. |
| Actions beyond re-running failed jobs | `actions.cancel-workflow-run`, `actions.force-cancel-workflow-run` | Stops runs people started. |
| | `actions.delete-workflow-run`, `actions.delete-workflow-run-logs`, `actions.delete-artifact` | Destroys CI history. |
| The user's own settings | `activity.set-repo-subscription`, `activity.delete-repo-subscription`, `activity.mark-repo-notifications-as-read` | About the credential's user, not the repository. |

### 6.3 Reads left out by choice

| Group | Operations | Why |
|---|---|---|
| Git data and archives | `git.get-*`, `git.list-matching-refs`, `repos.compare-commits`, `repos.list-tags`, `repos.get-readme`, `repos.get-readme-in-directory`, `repos.download-tarball-archive`, `repos.download-zipball-archive` | The clone answers them (`git log`, `git diff`, `git ls-remote --tags`). |
| More of the same resources | `pulls.list-comments-for-review`, `pulls.check-if-merged`, `pulls.list-requested-reviewers`, `issues.list-comments-for-repo`, `pulls.list-review-comments-for-repo`, `issues.list-labels-on-issue`, `pulls.get-merge-async-result`, pull request stacks, commit comments, issue events and timeline, assignees, milestones, sub-issues, dependencies, `repos.list-pull-requests-associated-with-commit`, `repos.list-branches-for-head-commit`, reactions | The listed reads already return this, or the workflows do not need it. |
| More CI | `checks.get`, check suites, `repos.list-commit-statuses-for-ref`, artifacts, timing, approvals, pending deployments, concurrency groups, deployments | The listed CI reads answer "what failed and why". |
| Security data | code scanning and Dependabot alerts, security advisories, attestations, SBOM and dependency graph, code quality, security settings (`code-security-configuration`, `immutable-releases`, `interaction-limits`) | Vulnerability details are not for agents; secret scanning and agent secrets and variables are in the Administration family (6.1). |
| Insights and people | traffic, stats, contributors, stargazers, watchers, forks, teams, events, activity, community profile, languages, license, topics, issue types, custom properties, CODEOWNERS errors, branch rules, installation, hash algorithm, the user's notifications and subscription | Not needed by the workflows. |
| Other | codespaces reads, `copilot.*`, source import status (`migrations.*`, deprecated) | Not needed by the workflows. |

## 7. v1

Useful beyond the agents that develop ghgw, and left for v1 (SPEC.md section 17). Each needs its
own review of abuse cases before it joins a preset.

| Operations | Why not in v0 | What v1 needs |
|---|---|---|
| `issues.add-labels`, `issues.list-labels-for-repo`, `issues.get-label` | Labels can drive merges, deploys and CI with secrets (auto-merge labels, labels that let a fork's code run with secrets). | Per-grant label allowlists, checked in the body. |
| `issues.create` | With push access GitHub takes `labels`, `assignees`, `milestone`, `type` and `parent_issue_id` in the body, so a new issue could carry the labels v0 leaves out, and assign and notify people. Not needed to work on pull requests. | The label allowlists above, and a decision on the other body fields. |
| Pull requests from another repository (`head` `owner:branch`, `head_repo`) | The source is a second repository, which the grant may not cover: its changes would show in the pull request's files and diff. Agents push to the repository they open the pull request in. | Resolving the source repository as GitHub does and requiring the calling agent's own read grant on it; another user's grant must not suffice. |
| `pulls.request-reviewers`, `pulls.remove-requested-reviewers`, `pulls.rerequest-reviewers` | Notifies people the agent picks. | A decision on who an agent may ask. |
| `actions.re-run-workflow`, `actions.re-run-job-for-workflow-run` | They re-run successful jobs too, e.g. a deploy. | A way to limit them to failed jobs, or a reason to accept the risk. |
| `repos.list-releases`, `repos.get-release`, `repos.get-latest-release`, `repos.get-release-by-tag`, release assets | Not needed to work on pull requests. | Path matching for tags (`{tag}` spans segments); assets are binary downloads. |
| `gh run` support: workflows (`actions.list-repo-workflows`, `actions.get-workflow`, `actions.list-workflow-runs`), run attempts with their jobs and logs, run and step logs, `checks.list-annotations` | `gh run view`, `watch` and `rerun` need these; v0 agents use `gh api` (section 2.5). Annotations need the "Checks" permission that fine-grained PATs lack. | GitHub App credentials for annotations; the re-run decision above for `gh run rerun`. |

## 8. Decisions

The maintainer's answers to the questions this proposal asked:

1. **Approvals.** `pulls.create-review` stays with `event: COMMENT` only; M7 denies `APPROVE` and
   `REQUEST_CHANGES` (sections 4.2 and 5.2).
2. **Check runs.** `checks.list-for-ref` stays, although fine-grained PATs lack the "Checks"
   permission (section 3).
3. **More `pr` writes.** No re-run of successful jobs and no review requests in v0 (section 7).
4. **Log redirects.** The gateway follows the redirect and streams the log; agents never get the
   signed URL (section 5.3).
5. **Labels.** No label writes in v0; v1 adds them with per-grant label allowlists (section 7).
   Not part of the decision: this proposal moves `issues.create` to v1 too, since its body takes
   labels.
6. **Gaps in the families.** A small `core` pull request before M7, separate from this one, adds
   the hard-rule writes that reached no family; section 6.1 includes them.
7. **Credential permissions.** SPEC.md section 7 lists the fine-grained PAT permissions v0 needs
   and recommends leaving out "Workflows" and "Administration". GitHub's permissions cannot stop
   merges (`pulls.merge` needs Contents write, which push needs too), so ghgw's hard rule is the
   only barrier.
8. **Parameters that span segments.** The last parameter of a `read` template may span segments,
   on the canonical path; bare `contents` is `repos.get-content` (section 5.1). Applied to
   `contents/{path}` and `branches/{branch}` only: a spanning `commits/{ref}` would also match
   commit reads that are left out.
9. **Identity.** No machine-user recommendation; GitHub App credentials are the v1 answer.
10. **`gh run`.** `gh api` only in v0; `gh run` support is v1 (section 7).

Not a preset question, noted for M8: `gh auth login --with-token` checks the token with
`GET /api/v3/` (the API root, for the `X-OAuth-Scopes` header) and a GraphQL `viewer { login }`
query; neither is in the table. M8's `ghgw setup` writes gh's host configuration
instead of running it (SPEC.md section 10).
