package t19_timelinex

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	core "github.com/ollie/phantomfs/internal/universe/core"
)

type Options struct {
	Inputs []string
	From   string
	To     string
}

type Event struct {
	TS     time.Time `json:"ts"`
	Source string    `json:"source"`
	Kind   string    `json:"kind"`
	Msg    string    `json:"msg"`
	Extra  string    `json:"extra,omitempty"`
}

var reSyslog = regexp.MustCompile(`^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+):\s+(.*)$`)

func Run(opts Options) (*core.Result, error) {
	r := core.NewResult("timelinex", strings.Join(opts.Inputs, ","))
	var events []Event
	seen := map[string]bool{}

	var fromT, toT time.Time
	var hasFrom, hasTo bool
	if opts.From != "" {
		if t, err := time.Parse(time.RFC3339, opts.From); err == nil {
			fromT, hasFrom = t, true
		}
	}
	if opts.To != "" {
		if t, err := time.Parse(time.RFC3339, opts.To); err == nil {
			toT, hasTo = t, true
		}
	}

	for _, in := range opts.Inputs {
		info, err := os.Stat(in)
		if err != nil {
			core.Warnf("skip %s: %v", in, err)
			continue
		}
		if info.IsDir() {
			filepath.Walk(in, func(p string, fi os.FileInfo, err error) error {
				if err != nil || fi.IsDir() {
					return nil
				}
				ingestFile(p, &events, seen)
				return nil
			})
		} else {
			ingestFile(in, &events, seen)
		}
	}

	// Filter
	var filtered []Event
	for _, e := range events {
		if hasFrom && e.TS.Before(fromT) {
			continue
		}
		if hasTo && e.TS.After(toT) {
			continue
		}
		filtered = append(filtered, e)
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].TS.Before(filtered[j].TS) })

	r.AddExtra("timeline", filtered)
	r.AddExtra("event_count", len(filtered))
	r.Add(core.Finding{Tool: "timelinex", Severity: core.SevInfo,
		Title: fmt.Sprintf("%d events", len(filtered))})
	r.Finish()
	return r, nil
}

func ingestFile(path string, events *[]Event, seen map[string]bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	// JSON array
	var jsonArr []map[string]any
	if json.Unmarshal(data, &jsonArr) == nil && len(jsonArr) > 0 {
		parseJSONEvents(jsonArr, path, events, seen)
		return
	}

	// Single JSON object with findings
	var single map[string]any
	if json.Unmarshal(data, &single) == nil {
		if findings, ok := single["findings"].([]any); ok {
			var arr []map[string]any
			for _, f := range findings {
				if m, ok := f.(map[string]any); ok {
					arr = append(arr, m)
				}
			}
			// Also use start_time as event
			if st, ok := single["start_time"].(string); ok {
				if t, err := time.Parse(time.RFC3339, st); err == nil {
					tool, _ := single["tool"].(string)
					*events = append(*events, Event{TS: t, Source: path, Kind: "report", Msg: tool})
				}
			}
			parseJSONEvents(arr, path, events, seen)
			return
		}
	}

	// JSONL
	lines := strings.Split(string(data), "\n")
	jsonl := false
	for _, l := range lines {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && (m["ts"] != nil || m["time"] != nil) {
			jsonl = true
			break
		}
	}
	if jsonl {
		var entries []map[string]any
		for _, l := range lines {
			var m map[string]any
			if json.Unmarshal([]byte(l), &m) == nil {
				entries = append(entries, m)
			}
		}
		parseJSONEvents(entries, path, events, seen)
		return
	}

	// wtmp
	if strings.HasSuffix(path, "wtmp") || looksBinary(data) {
		if parseWtmp(data, path, events, seen) {
			return
		}
	}

	// syslog
	parseSyslog(lines, path, events, seen)
}

func parseJSONEvents(arr []map[string]any, source string, events *[]Event, seen map[string]bool) {
	for _, m := range arr {
		tsStr := ""
		for _, k := range []string{"ts", "time", "timestamp", "added_at"} {
			if v, ok := m[k].(string); ok {
				tsStr = v
				break
			}
		}
		if tsStr == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, tsStr)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04:05", tsStr)
			if err != nil {
				continue
			}
		}
		kind := "event"
		if v, ok := m["kind"].(string); ok {
			kind = v
		} else if v, ok := m["title"].(string); ok {
			kind = v
		}
		msg := ""
		for _, k := range []string{"msg", "detail", "title"} {
			if v, ok := m[k].(string); ok && v != "" {
				msg = v
				break
			}
		}
		key := source + ":" + tsStr + ":" + msg
		if seen[key] {
			continue
		}
		seen[key] = true
		*events = append(*events, Event{TS: t, Source: source, Kind: kind, Msg: msg})
	}
}

func parseSyslog(lines []string, source string, events *[]Event, seen map[string]bool) {
	year := time.Now().Year()
	for _, line := range lines {
		m := reSyslog.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ts, err := time.Parse("Jan 2 15:04:05 2006",
			strings.Join(strings.Fields(m[1]), " ")+" "+itoa(year))
		if err != nil {
			continue
		}
		key := source + ":" + ts.Format(time.RFC3339) + ":" + m[4]
		if seen[key] {
			continue
		}
		seen[key] = true
		*events = append(*events, Event{
			TS: ts, Source: source, Kind: "syslog", Msg: m[4], Extra: m[2] + " " + m[3],
		})
	}
}

func parseWtmp(data []byte, source string, events *[]Event, seen map[string]bool) bool {
	const rec = 384
	if len(data) < rec {
		return false
	}
	parsed := 0
	for i := 0; i+rec <= len(data); i += rec {
		rec_ := data[i : i+rec]
		utType := int16(binary.LittleEndian.Uint16(rec_[0:2]))
		ts := int32(binary.LittleEndian.Uint32(rec_[340:344]))
		if ts <= 0 {
			continue
		}
		user := cstr(rec_[44:76])
		line := cstr(rec_[8:40])
		host := cstr(rec_[76:332])
		kind := "wtmp"
		switch utType {
		case 7:
			kind = "login"
		case 8:
			kind = "logout"
		case 2:
			kind = "boot"
		}
		t := time.Unix(int64(ts), 0)
		key := source + ":" + t.UTC().Format(time.RFC3339) + ":" + user
		if seen[key] {
			continue
		}
		seen[key] = true
		*events = append(*events, Event{
			TS: t, Source: source, Kind: kind, Msg: user + " tty=" + line, Extra: host,
		})
		parsed++
	}
	return parsed > 0
}

func looksBinary(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	zeros := 0
	n := 64
	if len(data) < n {
		n = len(data)
	}
	for _, c := range data[:n] {
		if c == 0 {
			zeros++
		}
	}
	return zeros > 8
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

var _ = bufio.NewReader
