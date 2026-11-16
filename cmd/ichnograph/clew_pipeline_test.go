package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClewPipelineExitCodes(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "in.json")
	output := filepath.Join(dir, "out.json")
	if err := os.WriteFile(input, []byte(`{"records":[{"pid":1,"tid":2,"success":true}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if got := runClew([]string{"-include", "invalid", "-o", output, input}); got != 2 {
		t.Fatalf("invalid predicate: %d", got)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("invalid arguments wrote output")
	}
	if got := runClew([]string{"-include", "success=true", "-tag", "ok:success=true", "-o", output, input}); got != 0 {
		t.Fatalf("valid invocation: %d", got)
	}
	if err := os.WriteFile(input, []byte(`{"records":[{}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(output)
	if got := runClew([]string{"-o", output, input}); got != 1 {
		t.Fatalf("invalid input: %d", got)
	}
	after, _ := os.ReadFile(output)
	if string(before) != string(after) {
		t.Fatal("invalid input changed output")
	}
}
