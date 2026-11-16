package clew

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Predicate struct {
	Field, Value string
	Substring    bool
}

var fieldName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func ParsePredicate(s string) (Predicate, error) {
	i := strings.Index(s, "=")
	if i < 1 {
		return Predicate{}, fmt.Errorf("invalid predicate %q", s)
	}
	field := s[:i]
	sub := strings.HasSuffix(field, "~")
	if sub {
		field = strings.TrimSuffix(field, "~")
	}
	value := s[i+1:]
	if !fieldName.MatchString(field) || value == "" {
		return Predicate{}, fmt.Errorf("invalid predicate %q", s)
	}
	return Predicate{field, value, sub}, nil
}

type Rule struct {
	Tag       string
	Predicate Predicate
}

func ParseRule(s string) (Rule, error) {
	tag, expr, ok := strings.Cut(s, ":")
	if !ok || !fieldName.MatchString(tag) {
		return Rule{}, fmt.Errorf("invalid tag rule %q", s)
	}
	p, e := ParsePredicate(expr)
	return Rule{tag, p}, e
}
func (p Predicate) match(m map[string]json.RawMessage) bool {
	raw, ok := m[p.Field]
	if !ok {
		return false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if p.Substring {
			return strings.Contains(s, p.Value)
		}
		return s == p.Value
	}
	if p.Substring {
		return false
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil && string(raw) != "null" {
		v, e := strconv.ParseBool(p.Value)
		return e == nil && (p.Value == "true" || p.Value == "false") && v == b
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil && string(raw) != "null" {
		a, ok := new(big.Rat).SetString(string(n))
		v, ok2 := new(big.Rat).SetString(p.Value)
		return ok && ok2 && a.Cmp(v) == 0
	}
	return false
}

type Detector interface{ Detect(string) []string }
type FileDetector struct{}

func (FileDetector) Detect(path string) []string {
	st, e := os.Stat(path)
	if e != nil || !st.Mode().IsRegular() {
		return nil
	}
	f, e := os.Open(path)
	if e != nil {
		return nil
	}
	defer f.Close()
	st, e = f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		return nil
	}
	buf := make([]byte, 4096)
	n, e := f.Read(buf)
	if e != nil && e != io.EOF {
		return nil
	}
	buf = buf[:n]
	if len(buf) >= 4 && string(buf[:4]) == "\x7fELF" {
		return []string{"elf"}
	}
	if strings.HasPrefix(string(buf), "#!") {
		line := strings.SplitN(string(buf), "\n", 2)[0]
		for _, s := range strings.Fields(line[2:]) {
			name := filepath.Base(s)
			switch name {
			case "ruby", "python", "python3", "sh", "bash":
				if name == "python3" {
					name = "python"
				}
				return []string{name}
			}
		}
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".rb":
		return []string{"ruby"}
	case ".py":
		return []string{"python"}
	case ".sh":
		return []string{"sh"}
	}
	return nil
}

type Options struct {
	Include, Exclude []Predicate
	Tags             []Rule
	Detector         Detector
}

func Process(data []byte, opts Options) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil || obj == nil {
		return nil, fmt.Errorf("invalid input JSON object")
	}
	_, groupedInput := obj["format"]
	var processes []map[string]json.RawMessage
	if groupedInput {
		validated, err := Group(data)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(validated, &obj); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(obj["processes"], &processes); err != nil {
			return nil, err
		}
	} else {
		var records []json.RawMessage
		if json.Unmarshal(obj["records"], &records) != nil || records == nil {
			return nil, fmt.Errorf("input must contain a records array")
		}
		for _, r := range records {
			var ids struct {
				PID *uint64 `json:"pid"`
				TID *uint64 `json:"tid"`
			}
			if json.Unmarshal(r, &ids) != nil || ids.PID == nil || ids.TID == nil {
				return nil, fmt.Errorf("record must contain numeric pid and tid")
			}
		}
		thread, _ := json.Marshal([]map[string]json.RawMessage{{"records": obj["records"]}})
		processes = []map[string]json.RawMessage{{"threads": thread}}
	}
	out := make([]map[string]json.RawMessage, 0, len(processes))
	cache := map[string][]string{}
	for _, p := range processes {
		var threads []map[string]json.RawMessage
		json.Unmarshal(p["threads"], &threads)
		keptThreads := make([]map[string]json.RawMessage, 0, len(threads))
		for _, t := range threads {
			var records []json.RawMessage
			json.Unmarshal(t["records"], &records)
			kept := make([]json.RawMessage, 0, len(records))
			for _, r := range records {
				var m map[string]json.RawMessage
				json.Unmarshal(r, &m)
				match := len(opts.Include) == 0
				for _, v := range opts.Include {
					if v.match(m) {
						match = true
					}
				}
				for _, v := range opts.Exclude {
					if v.match(m) {
						match = false
					}
				}
				if !match {
					continue
				}
				var add []string
				for _, rule := range opts.Tags {
					if rule.Predicate.match(m) {
						add = append(add, rule.Tag)
					}
				}
				if opts.Detector != nil {
					var path string
					json.Unmarshal(m["resolved_path"], &path)
					if path == "" {
						json.Unmarshal(m["path"], &path)
					}
					if path != "" {
						v, ok := cache[path]
						if !ok {
							v = opts.Detector.Detect(path)
							cache[path] = v
						}
						add = append(add, v...)
					}
				}
				if len(add) > 0 {
					var tags []string
					if existing, ok := m["tags"]; ok && json.Unmarshal(existing, &tags) != nil {
						return nil, fmt.Errorf("invalid tags array")
					}
					seen := map[string]bool{}
					for _, v := range tags {
						seen[v] = true
					}
					changed := false
					for _, v := range add {
						if !seen[v] {
							tags = append(tags, v)
							seen[v] = true
							changed = true
						}
					}
					if changed {
						m["tags"], _ = json.Marshal(tags)
						r, _ = json.Marshal(m)
					}
				}
				kept = append(kept, r)
			}
			if len(kept) > 0 {
				sortRecords(kept)
				t["records"], _ = json.Marshal(kept)
				keptThreads = append(keptThreads, t)
			}
		}
		if len(keptThreads) > 0 {
			p["threads"], _ = json.Marshal(keptThreads)
			out = append(out, p)
		}
	}
	if !groupedInput {
		records := json.RawMessage(`[]`)
		if len(out) > 0 {
			var threads []map[string]json.RawMessage
			json.Unmarshal(out[0]["threads"], &threads)
			records = threads[0]["records"]
		}
		obj["records"] = records
		raw, err := json.Marshal(obj)
		if err != nil {
			return nil, err
		}
		return Group(raw)
	}
	obj["processes"], _ = json.Marshal(out)
	result, err := json.MarshalIndent(obj, "", "  ")
	return append(result, '\n'), err
}

// sortRecords preserves input order for equal or unparseable timestamps.
func sortRecords(records []json.RawMessage) {
	type item struct {
		raw       json.RawMessage
		timestamp time.Time
		valid     bool
	}
	items := make([]item, len(records))
	for i, raw := range records {
		var v struct {
			Timestamp string `json:"timestamp"`
		}
		err := json.Unmarshal(raw, &v)
		ts, parseErr := time.Parse(time.RFC3339Nano, v.Timestamp)
		items[i] = item{raw, ts, err == nil && parseErr == nil}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].valid != items[j].valid {
			return items[i].valid
		}
		return items[i].valid && items[i].timestamp.Before(items[j].timestamp)
	})
	for i := range items {
		records[i] = items[i].raw
	}
}
