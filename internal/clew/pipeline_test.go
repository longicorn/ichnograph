package clew

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPipeline(t *testing.T) {
	p, _ := ParsePredicate("success=true")
	x, _ := ParsePredicate("path~=skip")
	rule, _ := ParseRule("ruby:path~=.rb")
	input := []byte(`{"records":[{"pid":1,"tid":2,"success":true,"path":"a.rb","tags":["old"],"extra":42},{"pid":1,"tid":3,"success":true,"path":"skip.rb"},{"pid":2,"tid":2,"success":false}]}`)
	result, err := Process(input, Options{Include: []Predicate{p}, Exclude: []Predicate{x}, Tags: []Rule{rule}})
	if err != nil {
		t.Fatal(err)
	}
	var obj struct {
		Processes []struct {
			Threads []struct {
				Records []map[string]any `json:"records"`
			} `json:"threads"`
		} `json:"processes"`
	}
	if err = json.Unmarshal(result, &obj); err != nil {
		t.Fatal(err)
	}
	if len(obj.Processes) != 1 || len(obj.Processes[0].Threads) != 1 {
		t.Fatalf("groups: %s", result)
	}
	rec := obj.Processes[0].Threads[0].Records[0]
	if rec["extra"] != float64(42) || len(rec["tags"].([]any)) != 2 {
		t.Fatalf("record: %s", result)
	}
	again, err := Process(result, Options{Tags: []Rule{rule}})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if json.Unmarshal(again, &decoded) != nil {
		t.Fatal("invalid JSON")
	}
}
func TestDetector(t *testing.T) {
	p := filepath.Join(t.TempDir(), "script")
	if err := os.WriteFile(p, []byte("#!/usr/bin/env ruby\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got := (FileDetector{}).Detect(p)
	if len(got) != 1 || got[0] != "ruby" {
		t.Fatal(got)
	}
}
func TestInvalidPredicates(t *testing.T) {
	for _, s := range []string{"", "=x", "path=", "bad field=x"} {
		if _, err := ParsePredicate(s); err == nil {
			t.Fatal(s)
		}
	}
}

type countingDetector struct{ calls []string }

func (d *countingDetector) Detect(p string) []string {
	d.calls = append(d.calls, p)
	return []string{"elf"}
}
func TestGroupedPreservationAndCache(t *testing.T) {
	input := []byte(`{"format":"ichnograph.clew.v1","extra":7,"processes":[{"pid":1,"metadata":"p","threads":[{"tid":2,"metadata":"t","records":[{"pid":1,"tid":2,"path":"fallback","resolved_path":"preferred"},{"pid":1,"tid":2,"resolved_path":"preferred"}]},{"tid":3,"records":[{"pid":1,"tid":3,"path":"skip"}]}]}]}`)
	exclude, _ := ParsePredicate("path=skip")
	d := &countingDetector{}
	got, err := Process(input, Options{Exclude: []Predicate{exclude}, Detector: d})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.calls) != 1 || d.calls[0] != "preferred" {
		t.Fatal(d.calls)
	}
	var obj map[string]any
	if err := json.Unmarshal(got, &obj); err != nil {
		t.Fatal(err)
	}
	ps := obj["processes"].([]any)
	p := ps[0].(map[string]any)
	ts := p["threads"].([]any)
	if obj["extra"] != float64(7) || p["metadata"] != "p" || len(ts) != 1 || ts[0].(map[string]any)["metadata"] != "t" {
		t.Fatalf("%s", got)
	}
}
func TestValidationBeforeFiltering(t *testing.T) {
	p, _ := ParsePredicate("success=true")
	_, err := Process([]byte(`{"records":[{"pid":1,"tid":2,"success":true},{"pid":1,"success":false}]}`), Options{Include: []Predicate{p}})
	if err == nil {
		t.Fatal("invalid excluded record accepted")
	}
}
func TestNumberPrecision(t *testing.T) {
	p, _ := ParsePredicate("id=9007199254740993")
	var m map[string]json.RawMessage
	json.Unmarshal([]byte(`{"id":9007199254740992}`), &m)
	if p.match(m) {
		t.Fatal("distinct integers matched")
	}
}

func TestGroupedInputRequiresGroupIDs(t *testing.T) {
	for _, input := range []string{
		`{"format":"ichnograph.clew.v1","processes":[{"threads":[{"tid":0,"records":[{"pid":0,"tid":0}]}]}]}`,
		`{"format":"ichnograph.clew.v1","processes":[{"pid":0,"threads":[{"records":[{"pid":0,"tid":0}]}]}]}`,
	} {
		if _, err := Process([]byte(input), Options{}); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}
