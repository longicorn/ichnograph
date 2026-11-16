package clew

import (
	"encoding/json"
	"fmt"
	"sort"
)

func Group(data []byte) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil || obj == nil {
		return nil, fmt.Errorf("invalid input JSON object")
	}
	var records []json.RawMessage
	if format, ok := obj["format"]; ok {
		var name string
		if json.Unmarshal(format, &name) != nil || name != "ichnograph.clew.v1" {
			return nil, fmt.Errorf("unsupported format")
		}
		var processes []struct {
			PID     *uint64 `json:"pid"`
			Threads []struct {
				TID     *uint64           `json:"tid"`
				Records []json.RawMessage `json:"records"`
			} `json:"threads"`
		}
		if string(obj["processes"]) == "null" || json.Unmarshal(obj["processes"], &processes) != nil || processes == nil {
			return nil, fmt.Errorf("invalid processes")
		}
		for _, p := range processes {
			if p.PID == nil || p.Threads == nil {
				return nil, fmt.Errorf("invalid threads")
			}
			for _, t := range p.Threads {
				if t.TID == nil || t.Records == nil {
					return nil, fmt.Errorf("invalid records")
				}
				for _, r := range t.Records {
					var ids struct {
						PID *uint64 `json:"pid"`
						TID *uint64 `json:"tid"`
					}
					if json.Unmarshal(r, &ids) != nil || ids.PID == nil || ids.TID == nil || *ids.PID != *p.PID || *ids.TID != *t.TID {
						return nil, fmt.Errorf("record does not match group")
					}
				}
			}
		}
		// Preserve group-level extensions and ordering on an already grouped input.
		result, err := json.MarshalIndent(obj, "", "  ")
		return append(result, '\n'), err
	}
	if json.Unmarshal(obj["records"], &records) != nil || records == nil {
		return nil, fmt.Errorf("input must contain a records array")
	}
	groups := map[uint64]map[uint64][]json.RawMessage{}
	for _, r := range records {
		var ids struct {
			PID *uint64 `json:"pid"`
			TID *uint64 `json:"tid"`
		}
		if json.Unmarshal(r, &ids) != nil || ids.PID == nil || ids.TID == nil {
			return nil, fmt.Errorf("record must contain numeric pid and tid")
		}
		if groups[*ids.PID] == nil {
			groups[*ids.PID] = map[uint64][]json.RawMessage{}
		}
		groups[*ids.PID][*ids.TID] = append(groups[*ids.PID][*ids.TID], r)
	}
	type thread struct {
		TID     uint64            `json:"tid"`
		Records []json.RawMessage `json:"records"`
	}
	type process struct {
		PID     uint64   `json:"pid"`
		Threads []thread `json:"threads"`
	}
	pids := make([]uint64, 0, len(groups))
	for p := range groups {
		pids = append(pids, p)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	processes := make([]process, 0, len(pids))
	for _, p := range pids {
		tids := make([]uint64, 0, len(groups[p]))
		for t := range groups[p] {
			tids = append(tids, t)
		}
		sort.Slice(tids, func(i, j int) bool { return tids[i] < tids[j] })
		v := process{PID: p, Threads: []thread{}}
		for _, t := range tids {
			v.Threads = append(v.Threads, thread{t, groups[p][t]})
		}
		processes = append(processes, v)
	}
	delete(obj, "records")
	obj["format"] = json.RawMessage(`"ichnograph.clew.v1"`)
	obj["processes"], _ = json.Marshal(processes)
	result, err := json.MarshalIndent(obj, "", "  ")
	return append(result, '\n'), err
}
