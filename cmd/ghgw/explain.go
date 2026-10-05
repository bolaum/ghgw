package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/bolaum/ghgw/internal/core"
	"github.com/spf13/cobra"
)

type explainFlags struct {
	policy, stateDir          string
	user, repo, op, defBranch string
	refs                      []string
}

func newExplainCmd() *cobra.Command {
	var (
		f      explainFlags
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Show what the policy decides for a request, without making it",
		Long: "Show the decision on a request and its reason, from the policy file and the owners in the\n" +
			"local store, without making the request.\n\n" +
			"--op is fetch, push or a REST operation name. A push without --ref asks whether the user\n" +
			"may push to the repository at all; with --ref, the push of those refs is decided ref by\n" +
			"ref, which needs the repository's default branch. A --ref is a branch name or a full ref\n" +
			"(refs/tags/v1); a leading ':' makes it a delete. The exit status is 0 whatever the\n" +
			"decision.",
		Example: "  ghgw explain --user rpi01-agent --repo bolaum/ghgw --op fetch\n" +
			"  ghgw explain --user rpi01-agent --repo bolaum/ghgw --op push\n" +
			"  ghgw explain --user rpi01-agent --repo bolaum/ghgw --op push --default-branch main \\\n" +
			"      --ref agent/fix-tests --ref main --ref :agent/old --json",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			req, err := f.request()
			if err != nil {
				return err
			}
			pf, err := loadPolicy(f.policy)
			if err != nil {
				return err
			}
			s, err := openStore(cmd.Context(), f.stateDir)
			if err != nil {
				return err
			}
			defer s.Close()
			owners, err := s.Owners(cmd.Context())
			if err != nil {
				return err
			}
			st := pf.State
			for _, o := range owners {
				st.Owners = append(st.Owners, o.Name)
			}
			// The REST operation table comes with the REST proxy (SPEC.md section 16, M7); until
			// then every REST operation is unknown, and denied.
			p, err := core.NewPolicy(st, nil)
			if err != nil {
				return err
			}
			d := p.Decide(req)
			w := cmd.OutOrStdout()
			if asJSON {
				return json.NewEncoder(w).Encode(newDecisionJSON(d))
			}
			_, err = fmt.Fprintln(w, d)
			return err
		},
	}
	addPolicyFlag(cmd, &f.policy)
	addStateDirFlag(cmd, &f.stateDir)
	cmd.Flags().StringVar(&f.user, "user", "", "the user making the request")
	cmd.Flags().StringVar(&f.repo, "repo", "", "the repository, owner/name")
	cmd.Flags().StringVar(&f.op, "op", "", "fetch, push, or a REST operation name")
	cmd.Flags().StringVar(&f.defBranch, "default-branch", "", "the repository's default branch, for a push with --ref")
	cmd.Flags().StringArrayVar(&f.refs, "ref", nil, "a ref the push updates (repeatable); ':ref' deletes it")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
	_ = cmd.MarkFlagRequired("user")
	_ = cmd.MarkFlagRequired("op")
	return cmd
}

// request builds the request the flags describe.
func (f explainFlags) request() (core.Request, error) {
	r := core.Request{User: f.user}
	if f.repo != "" {
		var err error
		if r.Repo, err = core.ParseRepo(f.repo); err != nil {
			return core.Request{}, err
		}
	}
	if f.op != "push" && (len(f.refs) > 0 || f.defBranch != "") {
		return core.Request{}, errors.New("--ref and --default-branch describe a push; use them with --op push")
	}
	switch {
	case f.op == "fetch":
		r.Op = core.Fetch{}
	case f.op == "push" && len(f.refs) == 0 && f.defBranch == "":
		r.Op = core.PushAccess{}
	case f.op == "push" && len(f.refs) == 0:
		return core.Request{}, errors.New("--default-branch needs the refs of the push: add --ref")
	case f.op == "push" && f.defBranch == "":
		return core.Request{}, errors.New("a push with --ref needs --default-branch: the push checks protect the repository's default branch")
	case f.op == "push":
		push := core.Push{DefaultBranch: f.defBranch}
		for _, ref := range f.refs {
			push.Updates = append(push.Updates, parseRefUpdate(ref))
		}
		r.Op = push
	default:
		r.Op = core.REST{Name: f.op}
	}
	return r, nil
}

// parseRefUpdate reads a --ref: a full ref or a branch name, with a leading ':' for a delete as in
// git push. Create and update follow the same rules, so both are an update here.
func parseRefUpdate(s string) core.RefUpdate {
	u := core.RefUpdate{Kind: core.UpdateRef}
	if rest, ok := strings.CutPrefix(s, ":"); ok {
		s, u.Kind = rest, core.DeleteRef
	}
	u.Ref = s
	if !strings.HasPrefix(s, "refs/") {
		u.Ref = "refs/heads/" + s
	}
	return u
}

// decisionJSON is a decision in --json output. Grant is null when no single grant allowed it.
type decisionJSON struct {
	Allowed bool       `json:"allowed"`
	Reason  string     `json:"reason"`
	Grant   *grantJSON `json:"grant"`
	Refs    []refJSON  `json:"refs,omitempty"`
}

type grantJSON struct {
	ID     int        `json:"id"`
	Holder holderJSON `json:"holder"`
}

type holderJSON struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type refJSON struct {
	Ref     string     `json:"ref"`
	Allowed bool       `json:"allowed"`
	Reason  string     `json:"reason"`
	Grant   *grantJSON `json:"grant"`
}

func newDecisionJSON(d core.Decision) decisionJSON {
	out := decisionJSON{Allowed: d.Allowed, Reason: d.Reason, Grant: newGrantJSON(d.Grant)}
	for _, rd := range d.Refs {
		out.Refs = append(out.Refs, refJSON{Ref: rd.Ref, Allowed: rd.Allowed, Reason: rd.Reason, Grant: newGrantJSON(rd.Grant)})
	}
	return out
}

func newGrantJSON(g core.GrantIdentity) *grantJSON {
	if g.ID == 0 {
		return nil
	}
	kind := "user"
	if g.Holder.Kind == core.HolderGroup {
		kind = "group"
	}
	return &grantJSON{ID: g.ID, Holder: holderJSON{Kind: kind, Name: g.Holder.Name}}
}
