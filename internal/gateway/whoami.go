package gateway

import (
	"net/http"

	"github.com/bolaum/ghgw/internal/core"
	"github.com/bolaum/ghgw/pkg/api"
)

// ghgwPrefix is reserved for ghgw's own endpoints (SPEC.md section 5).
const ghgwPrefix = "/_ghgw/"

// serveGhgw serves ghgw's own endpoints: whoami only in v0.
func (g *Gateway) serveGhgw(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != api.WhoamiPath {
		failJSON(w, http.StatusNotFound, "unknown ghgw endpoint; ghgw serves GET %s", api.WhoamiPath)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		failJSON(w, http.StatusMethodNotAllowed, "%s is read with GET", api.WhoamiPath)
		return
	}
	snap, user, ok := g.authenticate(w, r, failJSON)
	if !ok {
		return
	}
	id, err := snap.policy.Identity(user)
	if err != nil {
		failJSON(w, http.StatusForbidden, "%s", err)
		return
	}
	writeJSON(w, http.StatusOK, newWhoami(id))
}

func newWhoami(id core.Identity) api.Whoami {
	out := api.Whoami{User: id.User, Groups: id.Groups, Grants: []api.Grant{}}
	if out.Groups == nil {
		out.Groups = []string{}
	}
	for _, g := range id.Grants {
		ag := api.Grant{ID: g.ID, Holder: api.Holder{Kind: "user", Name: g.Holder.Name}, Access: string(g.Access), API: g.API.String(), Repos: []string{}, Push: []string{}}
		if g.Holder.Kind == core.HolderGroup {
			ag.Holder.Kind = "group"
		}
		for _, rg := range g.Repos {
			ag.Repos = append(ag.Repos, rg.String())
		}
		for _, b := range g.Push {
			ag.Push = append(ag.Push, b.String())
		}
		out.Grants = append(out.Grants, ag)
	}
	return out
}
