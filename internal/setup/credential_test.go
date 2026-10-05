package setup

import (
	"strings"
	"testing"

	"github.com/bolaum/ghgw/internal/store"
)

func TestCredential(t *testing.T) {
	key, _ := store.NewUserKey()
	c := Config{URL: "https://ghgw.example:8443", Key: key}
	answer := "username=ghgw\npassword=" + key.Reveal() + "\n"
	tests := []struct {
		name, action, in, want string
	}{
		{name: "get", action: "get", in: "protocol=https\nhost=ghgw.example:8443\nwwwauth[]=Basic realm=\"ghgw\"\n\n", want: answer},
		{name: "get without the blank line", action: "get", in: "protocol=https\nhost=GHGW.example:8443\n", want: answer},
		{name: "get with a path", action: "get", in: "protocol=https\nhost=ghgw.example:8443\npath=bolaum/ghgw.git\n\n", want: answer},
		{name: "another host", action: "get", in: "protocol=https\nhost=github.com\n\n"},
		{name: "another port", action: "get", in: "protocol=https\nhost=ghgw.example\n\n"},
		{name: "http", action: "get", in: "protocol=http\nhost=ghgw.example:8443\n\n"},
		{name: "no host", action: "get", in: "protocol=https\n\n"},
		{name: "attributes after the blank line", action: "get", in: "\nprotocol=https\nhost=ghgw.example:8443\n"},
		{name: "store", action: "store", in: "protocol=https\nhost=ghgw.example:8443\nusername=ghgw\npassword=x\n\n"},
		{name: "erase", action: "erase", in: "protocol=https\nhost=ghgw.example:8443\n\n"},
		{name: "unknown action", action: "capability", in: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out strings.Builder
			if err := Credential(tt.action, strings.NewReader(tt.in), &out, c); err != nil || out.String() != tt.want {
				t.Errorf("Credential() = %v, wrote %q; want %q", err, out.String(), tt.want)
			}
		})
	}
}
