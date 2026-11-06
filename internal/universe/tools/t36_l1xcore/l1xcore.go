// Package t36_l1xcore is the universal orchestrator: classify target,
// dispatch to the appropriate UNIVERSE tools in parallel, merge findings
// with dedupe, correlate entities across tools, and score aggregate risk.
package t36_l1xcore

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	core "github.com/ollie/phantomfs/internal/universe/core"
	t27_domainx "github.com/ollie/phantomfs/internal/universe/tools/t27_domainx"
	t28_identrace "github.com/ollie/phantomfs/internal/universe/tools/t28_identrace"
	t04_ipintel "github.com/ollie/phantomfs/internal/universe/tools/t04_ipintel"
	t05_userfinder "github.com/ollie/phantomfs/internal/universe/tools/t05_userfinder"
	t06_mailtrace "github.com/ollie/phantomfs/internal/universe/tools/t06_mailtrace"
	t35_certnexus "github.com/ollie/phantomfs/internal/universe/tools/t35_certnexus"
)

type dispatchResult struct {
	Tool string
	Res  *core.Result
	Err  error
}

func Run(target string) (*core.Result, error) {
	r := core.NewResult("l1xcore", target)
	target = strings.TrimSpace(target)
	kind := core.Classify(target)
	r.AddExtra("target_kind", string(kind))

	var tasks []struct {
		name string
		fn   func() (*core.Result, error)
	}

	switch kind {
	case core.IOCDomain:
		tasks = append(tasks,
			struct {
				name string
				fn   func() (*core.Result, error)
			}{"domainx", func() (*core.Result, error) { return t27_domainx.Run(target) }},
			struct {
				name string
				fn   func() (*core.Result, error)
			}{"certnexus", func() (*core.Result, error) { return t35_certnexus.Run(target) }},
		)
	case core.IOCURL:
		tasks = append(tasks,
			struct {
				name string
				fn   func() (*core.Result, error)
			}{"domainx", func() (*core.Result, error) { return t27_domainx.Run(extractHost(target)) }},
		)
	case core.IOCIPv4, core.IOCIPv6:
		tasks = append(tasks,
			struct {
				name string
				fn   func() (*core.Result, error)
			}{"ipintel", func() (*core.Result, error) { return t04_ipintel.Run(target) }},
		)
	case core.IOCEmail:
		tasks = append(tasks,
			struct {
				name string
				fn   func() (*core.Result, error)
			}{"mailtrace", func() (*core.Result, error) { return t06_mailtrace.Run(target) }},
			struct {
				name string
				fn   func() (*core.Result, error)
			}{"identrace", func() (*core.Result, error) { return t28_identrace.Run("", target) }},
		)
	default:
		tasks = append(tasks,
			struct {
				name string
				fn   func() (*core.Result, error)
			}{"userfinder", func() (*core.Result, error) { return t05_userfinder.Run(target) }},
			struct {
				name string
				fn   func() (*core.Result, error)
			}{"identrace", func() (*core.Result, error) { return t28_identrace.Run(target, "") }},
		)
	}

	var results []dispatchResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, t := range tasks {
		wg.Add(1)
		go func(name string, fn func() (*core.Result, error)) {
			defer wg.Done()
			res, err := fn()
			mu.Lock()
			results = append(results, dispatchResult{Tool: name, Res: res, Err: err})
			mu.Unlock()
		}(t.name, t.fn)
	}
	wg.Wait()

	// Merge findings with dedupe
	seen := map[string]bool{}
	entityCount := 0
	for _, dr := range results {
		if dr.Err != nil {
			r.Add(core.Finding{
				Tool: "l1xcore", Severity: core.SevLow,
				Title: "sub-tool error: " + dr.Tool, Detail: dr.Err.Error(),
			})
			continue
		}
		if dr.Res == nil {
			continue
		}
		for _, f := range dr.Res.Findings {
			key := f.Title + "|" + f.Detail
			if seen[key] {
				continue
			}
			seen[key] = true
			f.Tool = "l1xcore/" + dr.Tool
			r.Findings = append(r.Findings, f)
			entityCount++
		}
		r.AddExtra(dr.Tool, dr.Res.Extra)
	}
	r.AddExtra("sub_tools_run", len(results))
	r.AddExtra("deduped_findings", entityCount)

	// Correlate entities across subtool extras
	correlate(r)

	// Aggregate risk score
	score := 0
	for _, f := range r.Findings {
		switch f.Severity {
		case core.SevCrit:
			score += 20
		case core.SevHigh:
			score += 10
		case core.SevMed:
			score += 3
		}
	}
	r.AddExtra("risk_score", score)
	switch {
	case score >= 40:
		r.AddExtra("verdict", "high risk — multiple critical/high indicators")
	case score >= 15:
		r.AddExtra("verdict", "elevated risk")
	default:
		r.AddExtra("verdict", "baseline risk")
	}

	r.Finish()
	return r, nil
}

func correlate(r *core.Result) {
	// Cross-tool: look for shared IPs / domains across subtool extras
	ipSources := map[string][]string{}
	domainSources := map[string][]string{}

	for tool, extra := range r.Extra {
		if strings.HasPrefix(tool, "l1xcore") {
			continue
		}
		if ex, ok := extra.(map[string]any); ok {
			scanForEntities(ex, tool, ipSources, domainSources)
		}
	}

	correlations := []map[string]any{}
	for ip, sources := range ipSources {
		if len(sources) >= 2 {
			correlations = append(correlations, map[string]any{
				"type": "ip", "value": ip, "tools": sources,
			})
		}
	}
	for d, sources := range domainSources {
		if len(sources) >= 2 {
			correlations = append(correlations, map[string]any{
				"type": "domain", "value": d, "tools": sources,
			})
		}
	}
	sort.Slice(correlations, func(i, j int) bool {
		return correlations[i]["type"].(string) < correlations[j]["type"].(string)
	})
	r.AddExtra("correlations", correlations)
}

func scanForEntities(v any, tool string, ips, domains map[string][]string) {
	switch x := v.(type) {
	case string:
		if isIP(x) {
			ips[x] = appendUnique(ips[x], tool)
		} else if isDomainLike(x) {
			domains[x] = appendUnique(domains[x], tool)
		}
	case []any:
		for _, item := range x {
			scanForEntities(item, tool, ips, domains)
		}
	case []map[string]any:
		for _, item := range x {
			scanForEntities(item, tool, ips, domains)
		}
	case map[string]any:
		for _, item := range x {
			scanForEntities(item, tool, ips, domains)
		}
	}
}

func isIP(s string) bool {
	// cheap check
	if len(s) < 7 || len(s) > 45 {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func isDomainLike(s string) bool {
	if len(s) < 4 || len(s) > 253 {
		return false
	}
	if !strings.Contains(s, ".") {
		return false
	}
	if strings.Contains(s, "://") || strings.Contains(s, "@") || strings.Contains(s, " ") {
		return false
	}
	// Reject file paths
	if strings.ContainsAny(s, "/\\:") {
		return false
	}
	return true
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

func extractHost(raw string) string {
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/:?#"); i >= 0 {
		s = s[:i]
	}
	return s
}

var _ = fmt.Sprintf
