package main

import (
	"github.com/longicorn/ichnograph/internal/ebpf"
	"testing"
)

func TestFilterLogs(t *testing.T) {
	result := ebpf.Result{Records: []ebpf.Record{
		{Path: "/var/log/app"}, {Path: "app.log"}, {ResolvedPath: "/var/log/app/rotated"}, {ResolvedPath: "/tmp/app.log"},
		{Path: "/var/logging/app"}, {Path: "/tmp/app.log.1"}, {Path: ""},
	}}
	filterLogs(&result)
	if len(result.Records) != 3 || result.Records[0].Path != "/var/logging/app" || result.Records[1].Path != "/tmp/app.log.1" || result.Records[2].Path != "" {
		t.Fatalf("unexpected records: %+v", result.Records)
	}
	if len(result.Limitations) != 1 {
		t.Fatal("missing filtering limitation")
	}
}

func TestRunRejectsInvalidInvocation(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"-o", "out.json", "cmd"}, {"trace"}, {"trace", "-o", "out.json"}, {"trace", "cmd"}, {"trace", "-unknown"}} {
		if code := run(args); code != 2 {
			t.Errorf("run(%q) = %d, want 2", args, code)
		}
	}
}
