package core

// Request is one decision to make: may User do Op on Repo?
type Request struct {
	// User is the authenticated ghgw user.
	User string
	// Repo is zero for operations that are not repository-scoped.
	Repo Repo
	Op   Operation
}

// Operation is what a request does: Fetch, Push or REST.
type Operation interface {
	// operation returns the name used in reasons.
	operation() string
}

// Fetch is a git fetch or clone (upload-pack). It needs read access.
type Fetch struct{}

func (Fetch) operation() string { return "fetch" }

// Push is a git push (receive-pack). It needs write access, and every ref update must be allowed:
// pushes are all-or-nothing.
type Push struct {
	// DefaultBranch is the repository's default branch, without "refs/heads/". A push with
	// updates and no default branch is denied: the default branch rule could not be checked.
	DefaultBranch string
	// Updates are the ref update commands in the order the client sent them. A push without
	// updates checks write access only, e.g. before the receive-pack ref advertisement.
	Updates []RefUpdate
}

func (Push) operation() string { return "push" }

// RefUpdate is one command of a push.
type RefUpdate struct {
	// Ref is the full ref name, e.g. "refs/heads/agent/x" or "refs/tags/v1".
	Ref  string
	Kind RefUpdateKind
}

// RefUpdateKind is what a ref update does. Force pushes are updates like any other.
type RefUpdateKind int

const (
	CreateRef RefUpdateKind = iota + 1
	UpdateRef
	DeleteRef
)

// REST is a REST API call, classified as the operation of the policy's REST table called Name
// ("pulls.create"). Unknown operations are denied.
type REST struct {
	Name string
}

func (o REST) operation() string { return o.Name }
