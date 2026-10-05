package core

// The REST operation table of v0: what the agents developing ghgw need to work on pull requests
// through gh api (SPEC.md section 16). docs/operations.md gives the reasons and the abuse cases of
// every entry; change both together. Names are GitHub's operationId with '/' replaced by '.'.
var operations = []RESTOperation{
	// read
	{"repos.get", "GET", "/repos/{owner}/{repo}", ClassRead},
	{"repos.get-content", "GET", "/repos/{owner}/{repo}/contents/{path}", ClassRead},
	{"repos.list-branches", "GET", "/repos/{owner}/{repo}/branches", ClassRead},
	{"repos.get-branch", "GET", "/repos/{owner}/{repo}/branches/{branch}", ClassRead},
	{"repos.list-commits", "GET", "/repos/{owner}/{repo}/commits", ClassRead},
	{"repos.get-commit", "GET", "/repos/{owner}/{repo}/commits/{ref}", ClassRead},
	{"pulls.list", "GET", "/repos/{owner}/{repo}/pulls", ClassRead},
	{"pulls.get", "GET", "/repos/{owner}/{repo}/pulls/{pull_number}", ClassRead},
	{"pulls.list-commits", "GET", "/repos/{owner}/{repo}/pulls/{pull_number}/commits", ClassRead},
	{"pulls.list-files", "GET", "/repos/{owner}/{repo}/pulls/{pull_number}/files", ClassRead},
	{"pulls.list-reviews", "GET", "/repos/{owner}/{repo}/pulls/{pull_number}/reviews", ClassRead},
	{"pulls.get-review", "GET", "/repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}", ClassRead},
	{"pulls.list-review-comments", "GET", "/repos/{owner}/{repo}/pulls/{pull_number}/comments", ClassRead},
	{"pulls.get-review-comment", "GET", "/repos/{owner}/{repo}/pulls/comments/{comment_id}", ClassRead},
	{"issues.list-for-repo", "GET", "/repos/{owner}/{repo}/issues", ClassRead},
	{"issues.get", "GET", "/repos/{owner}/{repo}/issues/{issue_number}", ClassRead},
	{"issues.list-comments", "GET", "/repos/{owner}/{repo}/issues/{issue_number}/comments", ClassRead},
	{"issues.get-comment", "GET", "/repos/{owner}/{repo}/issues/comments/{comment_id}", ClassRead},
	{"checks.list-for-ref", "GET", "/repos/{owner}/{repo}/commits/{ref}/check-runs", ClassRead},
	{"repos.get-combined-status-for-ref", "GET", "/repos/{owner}/{repo}/commits/{ref}/status", ClassRead},
	{"actions.list-workflow-runs-for-repo", "GET", "/repos/{owner}/{repo}/actions/runs", ClassRead},
	{"actions.get-workflow-run", "GET", "/repos/{owner}/{repo}/actions/runs/{run_id}", ClassRead},
	{"actions.list-jobs-for-workflow-run", "GET", "/repos/{owner}/{repo}/actions/runs/{run_id}/jobs", ClassRead},
	{OpDownloadJobLogs, "GET", "/repos/{owner}/{repo}/actions/jobs/{job_id}/logs", ClassRead},

	// pr
	{OpCreatePull, "POST", "/repos/{owner}/{repo}/pulls", ClassPR},
	{"pulls.update", "PATCH", "/repos/{owner}/{repo}/pulls/{pull_number}", ClassPR},
	{"issues.create-comment", "POST", "/repos/{owner}/{repo}/issues/{issue_number}/comments", ClassPR},
	{OpCreateReview, "POST", "/repos/{owner}/{repo}/pulls/{pull_number}/reviews", ClassPR},
	{"pulls.create-reply-for-review-comment", "POST", "/repos/{owner}/{repo}/pulls/{pull_number}/comments/{comment_id}/replies", ClassPR},
	{"actions.re-run-workflow-failed-jobs", "POST", "/repos/{owner}/{repo}/actions/runs/{run_id}/rerun-failed-jobs", ClassPR},

	// global
	{"rate-limit.get", "GET", "/rate_limit", ClassGlobal},
	{"meta.get", "GET", "/meta", ClassGlobal},
}

// The operations a transport treats specially.
const (
	// OpCreatePull and OpCreateReview are forwarded only with a body CheckBody accepts.
	OpCreatePull   = "pulls.create"
	OpCreateReview = "pulls.create-review"
	// OpDownloadJobLogs answers with a redirect to a signed storage URL, which the gateway follows
	// itself so agents never get it.
	OpDownloadJobLogs = "actions.download-job-logs-for-workflow-run"
)

var defaultTable = mustRESTTable(operations)

func mustRESTTable(ops []RESTOperation) *RESTTable {
	t, err := NewRESTTable(ops)
	if err != nil {
		panic(err)
	}
	return t
}

// DefaultRESTTable returns the operation table of v0. It is read-only and safe for concurrent use.
func DefaultRESTTable() *RESTTable { return defaultTable }
