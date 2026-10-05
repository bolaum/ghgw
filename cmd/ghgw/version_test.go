package main

import (
	"bytes"
	"testing"
)

func TestVersion(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{
			name: "text",
			args: []string{"version"},
			want: "ghgw dev (commit unknown, built unknown)\n",
		},
		{
			name: "json",
			args: []string{"version", "--json"},
			want: `{"version":"dev","commit":"unknown","date":"unknown"}` + "\n",
		},
		{
			name:    "extra argument",
			args:    []string{"version", "extra"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			cmd := newRootCmd()
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && out.String() != tt.want {
				t.Errorf("output = %q, want %q", out.String(), tt.want)
			}
		})
	}
}
