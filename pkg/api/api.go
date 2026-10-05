// Package api holds the JSON types of ghgw's HTTP endpoints that its clients share.
package api

// WhoamiPath is the gateway's whoami endpoint (SPEC.md section 5.5).
const WhoamiPath = "/_ghgw/whoami"

// Whoami is the answer of GET WhoamiPath: who the key belongs to and what it may do.
type Whoami struct {
	User   string   `json:"user"`
	Groups []string `json:"groups"`
	// Grants are the user's effective grants, its own and those of its groups, ordered by ID.
	Grants []Grant `json:"grants"`
}

// Grant is a grant as the policy file writes it.
type Grant struct {
	ID     int      `json:"id"`
	Holder Holder   `json:"holder"`
	Repos  []string `json:"repos"`
	// Access is read or write.
	Access string   `json:"access"`
	Push   []string `json:"push"`
	// API is the preset: read, pr, or none.
	API string `json:"api"`
}

// Holder is the user or group a grant is attached to; Kind is user or group.
type Holder struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}
