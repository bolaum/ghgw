package core

import (
	"fmt"
	"slices"
	"testing"
)

func TestIdentity(t *testing.T) {
	p, err := NewPolicy(State{
		Users: []User{{Name: "rpi01-agent"}, {Name: "idle"}, {Name: "off", Disabled: true}},
		Groups: []Group{
			{Name: "reviewers", Members: []string{"rpi01-agent"}},
			{Name: "agents", Members: []string{"rpi01-agent", "off"}},
		},
		Grants: []Grant{
			grant(t, 3, "user rpi01-agent", []string{"acme/ml-lab"}, AccessWrite, []string{"agent/**"}, PresetPR),
			grant(t, 2, "group reviewers", []string{"acme/app"}, AccessRead, nil, PresetPR),
			grant(t, 1, "group agents", []string{"bolaum/*", "acme/docs"}, AccessRead, nil, PresetRead),
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		user       string
		wantGroups []string
		wantGrants []string
		wantErr    string
	}{
		{user: "rpi01-agent", wantGroups: []string{"agents", "reviewers"}, wantGrants: []string{
			"grant 1 of group agents: [bolaum/* acme/docs] read [] read",
			"grant 2 of group reviewers: [acme/app] read [] pr",
			"grant 3 of user rpi01-agent: [acme/ml-lab] write [agent/**] pr",
		}},
		{user: "idle"},
		{user: "off", wantErr: "user off is disabled; ask the admin to enable it"},
		{user: "ghost", wantErr: "unknown user ghost; ask the admin to create it"},
	}
	for _, tt := range tests {
		t.Run(tt.user, func(t *testing.T) {
			id, err := p.Identity(tt.user)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("Identity() = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var grants []string
			for _, g := range id.Grants {
				grants = append(grants, fmt.Sprintf("%s: %v %s %v %s", g, g.Repos, g.Access, g.Push, g.API))
			}
			if id.User != tt.user || !slices.Equal(id.Groups, tt.wantGroups) || !slices.Equal(grants, tt.wantGrants) {
				t.Errorf("Identity() = %s %q %q, want %q %q", id.User, id.Groups, grants, tt.wantGroups, tt.wantGrants)
			}
		})
	}

	// The identity is a copy: changing it changes no decision.
	id, _ := p.Identity("rpi01-agent")
	id.Groups[0] = "x"
	id.Grants[0].Repos[0] = id.Grants[2].Repos[0]
	if again, _ := p.Identity("rpi01-agent"); again.Groups[0] != "agents" || again.Grants[0].Repos[0].String() != "bolaum/*" {
		t.Error("changing an identity changed the policy")
	}
}
