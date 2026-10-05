# ghgw

GitHub gateway for coding agents. ghgw sits between agents and GitHub and holds the real
credentials: each agent gets its own ghgw key, and every `git` or `gh` request is checked against
a deny-by-default policy, sent to GitHub with the repository owner's credential, and audited.
Agents never hold a GitHub token.

Status: pre-alpha. Nothing works yet beyond `ghgw version`.

[SPEC.md](SPEC.md) describes the design and is the source of truth for behavior;
[CLAUDE.md](CLAUDE.md) is the contributor guide.

## Build

Requires Go (see `go.mod`) and `make`.

```
make all     # vet, lint, test, build
./bin/ghgw version
```
