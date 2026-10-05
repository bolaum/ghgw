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
| `issues.list-labels-for-repo` | GET | `/repos/{owner}/{repo}/labels` | The labels that exist, so the agent adds those rather than invent names. | [docs](https://docs.github.com/rest/issues/labels#list-labels-for-a-repository) |
| `repos.list-releases` | GET | `/repos/{owner}/{repo}/releases` | Versions and release notes. | [docs](https://docs.github.com/rest/releases/releases#list-releases) |
| `repos.get-release-by-tag` | GET | `/repos/{owner}/{repo}/releases/tags/{tag}` | The release of a known tag. | [docs](https://docs.github.com/rest/releases/releases#get-a-release-by-tag-name) |
| `checks.list-for-ref` | GET | `/repos/{owner}/{repo}/commits/{ref}/check-runs` | CI results of a commit, from Actions and other apps (open question 2). | [docs](https://docs.github.com/rest/checks/runs#list-check-runs-for-a-git-reference) |
| `repos.get-combined-status-for-ref` | GET | `/repos/{owner}/{repo}/commits/{ref}/status` | CI results reported as commit statuses (older integrations). | [docs](https://docs.github.com/rest/commits/statuses#get-the-combined-status-for-a-specific-reference) |
| `actions.list-workflow-runs-for-repo` | GET | `/repos/{owner}/{repo}/actions/runs` | The runs of a branch or a commit (`branch=`, `head_sha=`). | [docs](https://docs.github.com/rest/actions/workflow-runs#list-workflow-runs-for-a-repository) |
| `actions.get-workflow-run` | GET | `/repos/{owner}/{repo}/actions/runs/{run_id}` | One run's status, e.g. after a re-run. | [docs](https://docs.github.com/rest/actions/workflow-runs#get-a-workflow-run) |
| `actions.list-jobs-for-workflow-run` | GET | `/repos/{owner}/{repo}/actions/runs/{run_id}/jobs` | Which jobs and steps failed. | [docs](https://docs.github.com/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run) |
| `actions.download-job-logs-for-workflow-run` | GET | `/repos/{owner}/{repo}/actions/jobs/{job_id}/logs` | The log of a failed job: what the agent fixes from. | [docs](https://docs.github.com/rest/actions/workflow-jobs#download-job-logs-for-a-workflow-run) |

What `read` exposes beyond a clone: issues, pull requests, comments and CI logs of the granted
repositories. GitHub masks registered secrets in logs, but a workflow can still print something
sensitive that is not registered as a secret; whoever may read CI on GitHub reads the same logs.

## 4. The `pr` preset

`pr` is `read` plus these entries.

| Name | Method | Path | Rationale | Docs |
|---|---|---|---|---|
| `pulls.create` | POST | `/repos/{owner}/{repo}/pulls` | Open a pull request from a pushed branch. | [docs](https://docs.github.com/rest/pulls/pulls#create-a-pull-request) |
| `pulls.update` | PATCH | `/repos/{owner}/{repo}/pulls/{pull_number}` | Keep the title and body current; close a pull request the agent gives up on. | [docs](https://docs.github.com/rest/pulls/pulls#update-a-pull-request) |
| `issues.create-comment` | POST | `/repos/{owner}/{repo}/issues/{issue_number}/comments` | Comment on a pull request or an issue (the conversation, not a line). | [docs](https://docs.github.com/rest/issues/comments#create-an-issue-comment) |
| `pulls.create-review` | POST | `/repos/{owner}/{repo}/pulls/{pull_number}/reviews` | Review a pull request: a summary and line comments in one call. | [docs](https://docs.github.com/rest/pulls/reviews#create-a-review-for-a-pull-request) |
| `pulls.create-reply-for-review-comment` | POST | `/repos/{owner}/{repo}/pulls/{pull_number}/comments/{comment_id}/replies` | Answer a line comment in its thread. | [docs](https://docs.github.com/rest/pulls/comments#create-a-reply-for-a-review-comment) |
| `issues.create` | POST | `/repos/{owner}/{repo}/issues` | Report a problem found while working. | [docs](https://docs.github.com/rest/issues/issues#create-an-issue) |
| `issues.add-labels` | POST | `/repos/{owner}/{repo}/issues/{issue_number}/labels` | Label an issue or a pull request with existing labels. | [docs](https://docs.github.com/rest/issues/labels#add-labels-to-an-issue) |
| `actions.re-run-workflow-failed-jobs` | POST | `/repos/{owner}/{repo}/actions/runs/{run_id}/rerun-failed-jobs` | Re-run the failed jobs of a run, e.g. after a flaky failure. | [docs](https://docs.github.com/rest/actions/workflow-runs#re-run-failed-jobs-from-a-workflow-run) |

### 4.1 What limits every `pr` entry

- Only the granted repositories, and every request is in ghgw's audit with the agent's name.
- No `pr` entry changes code, merges, releases, reports a CI result or starts a workflow of its
  own choosing: those are hard rules. What is left is noise, misleading text, and whatever
  automation reacts to pull requests, comments and labels.
- Everything shows in the repository's timeline and a person can undo it (reopen, edit, remove a
  label); only the notifications already sent stay.
- GitHub's secondary rate limits on content creation cap spam until ghgw has per-user rate
  limits (v1).
- The table has no edits or deletes of comments and reviews, so an agent cannot rewrite or hide
  what was said (section 5.3).

Two risks are common to several entries and limited by the admin, not by the table:

- **Automation that trusts the credential's user.** Writes are authored by the PAT's user, often
  a maintainer. Bots and workflows that act on a maintainer's comment (`/deploy`, `/merge`,
  `/ok-to-test`) or label (auto-merge labels, labels that let a fork's code run with secrets)
  obey an agent just as well, and ghgw does not read bodies. The admin should not give `pr` on a
  repository where a comment or a label from that user merges, deploys or runs untrusted code.
- **CI runs the agent's code.** A pushed branch, and the pull request opened from it, run the
  repository's workflows on the agent's code, with whatever secrets those workflows expose. This
  comes with push access (M5) more than with `pr`. Leaving the "Workflows" permission off the PAT
  makes GitHub reject pushes that change `.github/workflows/`, so an agent cannot write a new
  workflow; the existing ones still run its code (open question 7).

### 4.2 Abuse, entry by entry

**`pulls.create`**

- Abuse: pull request spam; a pull request from a branch the agent did not write (any branch of
  the repository, or a fork's `user:branch`) into any base branch; turning someone's issue into a
  pull request (`issue`); a misleading title or body that a person merges on trust.
- Limits: opening a pull request merges nothing, and merging is a hard rule. Code in a branch of
  the repository got there through the push checks or a person. The `pull_request` workflows it
  triggers run the same code that the push already ran in most repositories (4.1). Acceptable.

**`pulls.update`**

- Abuse: edit the title and body of any pull request, people's included; close any pull request;
  change its base branch; turn `maintainer_can_modify` off on a fork's pull request.
- Limits: the timeline records title and base changes and closes, GitHub keeps the edit history
  of the body, and a person reverts or reopens. Restricting it to the agent's own pull requests is
  not possible by path, nor by author: agents and the owner share one GitHub user. Acceptable.

**`issues.create-comment`**

- Abuse: comment spam and `@mention` spam; text that reads as the owner's own words; commands to
  bots and `issue_comment` workflows (4.1).
- Limits: the agent cannot edit or delete comments afterwards; people can. Command automation is
  the admin's to know (4.1). Acceptable with that guidance.

**`pulls.create-review`**

- Abuse: `APPROVE` counts toward required reviews, and toward code owner reviews when the PAT's
  user is a code owner, so a prompt-injected agent can approve someone else's malicious pull
  request and a person merges it on trust. `REQUEST_CHANGES` can block a merge until someone
  dismisses it. Line comment spam.
- Limits: GitHub does not let a pull request's author approve it, and every pull request an agent
  opens is authored by the PAT's user, so agents cannot approve their own work. ghgw cannot see
  `event`, which is in the body. Proposed as is; open question 1 asks whether M7 should read the
  body and deny `APPROVE`.

**`pulls.create-reply-for-review-comment`**

- Abuse: reply spam; replying "fixed" without fixing.
- Limits: as for comments. Resolving a thread is GraphQL only, so the reviewer still sees every
  thread open and checks the answer. Acceptable.

**`issues.create`**

- Abuse: issue spam. With push access GitHub also takes `labels`, `assignees`, `milestone`,
  `type` and `parent_issue_id` in the body, so a new issue can carry labels (4.1) and assign and
  notify people. `issues` workflows run, with the default branch's workflow files.
- Limits: issues change no code and a person closes them; labels behave as with
  `issues.add-labels`. Acceptable.

**`issues.add-labels`**

- Abuse: label spam on any issue or pull request; labels that drive automation (auto-merge,
  deploy, "safe to test" labels, see 4.1). GitHub does not document whether a name that does not
  exist yet is created; M7's end-to-end test should find out.
- Limits: removing and replacing labels are not in the table, so an agent cannot take off a
  blocking label (`do-not-merge`) or a person's triage. Label automation is the admin's to know
  (4.1); open question 5 asks about per-grant label lists. Acceptable with that guidance.

**`actions.re-run-workflow-failed-jobs`**

- Abuse: re-run the failed jobs of any run, deploy and release jobs included, with the jobs that
  depend on them; burn Actions minutes by re-running in a loop; `enable_debug_logging` makes the
  runner log more.
- Limits: a re-run uses the original run's commit, ref and workflow files, and the privileges of
  the actor who triggered the run, not those of the one who re-runs it
  ([docs](https://docs.github.com/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs)):
  it runs no new code and gains nothing. Only runs from the last 30 days can be re-run. Debug logs
  still mask secrets. Acceptable.
