package main

import (
	"bytes"
	"runtime/debug"
	"testing"
)

func TestVersionCmd(t *testing.T) {
	// Set the ldflags variables so the output does not depend on the test binary's build info.
	t.Cleanup(func() { version, commit, date = "", "", "" })
	version, commit, date = "v1.2.3", "abc1234", "2026-01-02T03:04:05Z"

	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{
			name: "text",
			args: []string{"version"},
			want: "ghgw v1.2.3 (commit abc1234, built 2026-01-02T03:04:05Z)\n",
		},
		{
			name: "json",
			args: []string{"version", "--json"},
			want: `{"version":"v1.2.3","commit":"abc1234","date":"2026-01-02T03:04:05Z"}` + "\n",
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

func TestResolveVersion(t *testing.T) {
	buildInfo := &debug.BuildInfo{
		Main: debug.Module{Version: "v0.1.0"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "fedcba9876543210"},
			{Key: "vcs.time", Value: "2026-03-04T05:06:07Z"},
		},
	}
	ldflags := versionInfo{Version: "v9.9.9", Commit: "abc1234", Date: "2026-01-02T03:04:05Z"}

	tests := []struct {
		name    string
		ldflags versionInfo
		bi      *debug.BuildInfo
		want    versionInfo
	}{
		{
			name:    "ldflags win over build info",
			ldflags: ldflags,
			bi:      buildInfo,
			want:    ldflags,
		},
		{
			name:    "build info fills what ldflags left empty",
			ldflags: versionInfo{Commit: "abc1234"},
			bi:      buildInfo,
			want:    versionInfo{Version: "v0.1.0", Commit: "abc1234", Date: "2026-03-04T05:06:07Z"},
		},
		{
			name: "devel build without vcs info",
			bi:   &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}},
			want: versionInfo{Version: "dev", Commit: "unknown", Date: "unknown"},
		},
		{
			name: "no build info",
			want: versionInfo{Version: "dev", Commit: "unknown", Date: "unknown"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveVersion(tt.ldflags, tt.bi); got != tt.want {
				t.Errorf("resolveVersion() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
