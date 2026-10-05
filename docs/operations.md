# REST operations

Status: proposal (milestone M6), waiting for the maintainer's approval. Nothing here is
implemented yet: M7 turns the tables below into the operation table of `internal/core`, with
tests.

This document proposes the REST operations of the `read` and `pr` presets (SPEC.md section 5.3).
The table is the allow-list: anything it does not list is denied. It only lists what the
workflows of section 2 need.

## 1. Conventions

- Names, methods, path templates and documentation links come from GitHub's OpenAPI description
  of api.github.com ([github/rest-api-description](https://github.com/github/rest-api-description),
  fetched 2026-10-05). A name is GitHub's `operationId` with `/` replaced by `.` (`pulls/create`
  becomes `pulls.create`), so every name can be looked up in GitHub's description.
- Every entry passes `NewRESTTable` with its class: canonical path template, `GET` for `read`, and
  no hard-rule family reachable.
- ghgw classifies a request by method and path only; bodies and query strings are not read. Each
  entry is judged on the worst body GitHub accepts for it.
- Every request runs with the owner's credential, so on GitHub every write is authored by the
  user who owns the PAT, whichever agent made it. Only ghgw's audit tells which agent it was.
- Every grant has git access, at least `read`. The REST reads therefore expose no code beyond what
  a clone gives; what they add is the collaboration data (issues, pull requests, comments) and CI.

## 2. Workflows

What an agent does with the presets, all through `gh api` (no GraphQL in v0). `gh api` fills in
`{owner}` and `{repo}` from the repository in the current directory. The comment on each line is
the operation the gateway classifies the request as. Numbers (pull request 42, run 1234, ...) are
examples.

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
gh api repos/{owner}/{repo}/branches/main --jq .commit.sha                # repos.get-branch
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
gh api repos/{owner}/{repo}/labels --paginate --jq '.[].name'            # issues.list-labels-for-repo
```

### 2.5 Releases (`read`)

```sh
gh api repos/{owner}/{repo}/releases --jq '.[].tag_name'                 # repos.list-releases
gh api repos/{owner}/{repo}/releases/tags/v1.2.0 --jq .body              # repos.get-release-by-tag
```

### 2.6 CI (`read`)

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

The log endpoint answers with a redirect to a signed URL on a GitHub storage host, valid for one
minute. The gateway does not rewrite that `Location` (it is not api.github.com), so `gh` fetches
the log from GitHub directly, without the ghgw key (open question 4).

### 2.7 Open, update and comment on a pull request (`pr`)

```sh
git push origin agent/fix-42                                             # git, through the push checks
gh api -X POST repos/{owner}/{repo}/pulls -f head=agent/fix-42 -f base=main \
  -f title='core: fix the glob cut' -F body=@pr.md                       # pulls.create
gh api -X PATCH repos/{owner}/{repo}/pulls/42 -F body=@pr.md             # pulls.update
gh api -X PATCH repos/{owner}/{repo}/pulls/42 -f state=closed            # pulls.update
gh api -X POST repos/{owner}/{repo}/issues/42/comments \
  -f body='Rebased on main; CI is green.'                                # issues.create-comment
```

Marking a draft pull request ready for review is GraphQL only, so an agent that opens a draft
leaves that step to a person.

### 2.8 Review a pull request and reply to review comments (`pr`)

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

A review without `event` stays pending and nobody sees it; submitting a pending review is not in
the table, so agents always pass `event`.

### 2.9 Create and comment on issues, add labels (`pr`)

```sh
gh api -X POST repos/{owner}/{repo}/issues \
  -f title='glob: ** accepted after a slash' -F body=@issue.md           # issues.create
gh api -X POST repos/{owner}/{repo}/issues/17/comments -F body=@note.md  # issues.create-comment
gh api -X POST repos/{owner}/{repo}/issues/17/labels -f 'labels[]=bug'   # issues.add-labels
```

Labels go on pull requests the same way, by their number.

### 2.10 Re-run failed jobs (`pr`)

```sh
gh api -X POST repos/{owner}/{repo}/actions/runs/1234/rerun-failed-jobs # actions.re-run-workflow-failed-jobs
gh api repos/{owner}/{repo}/actions/runs/1234 --jq '[.status, .conclusion]'  # actions.get-workflow-run
```
