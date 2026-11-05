// Package intel — Cyber Intelligence Engine.
// Enriches IOCs against URLhaus, ThreatFox, and ip-api geo.
package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/ollie/phantomfs/internal/cyber/core"
)

const (
	urlhausHost = "https://urlhaus-api.abuse.ch/v1/host/"
	urlhausURL  = "https://urlhaus-api.abuse.ch/v1/url/"
	threatfox   = "https://threatfox-api.abuse.ch/api/v1/"
	geoAPI      = "http://ip-api.com/json/%s?fields=status,country,countryCode,regionName,city,isp,org,as,query"
)

type intel struct {
	IOC       string         `json:"ioc"`
	Kind      string         `json:"kind"`
	Geo       map[string]any `json:"geo,omitempty"`
	URLHaus   map[string]any `json:"urlhaus,omitempty"`
	ThreatFox map[string]any `json:"threatfox,omitempty"`
	Score     int            `json:"score"`
	Reasons   []string       `json:"reasons,omitempty"`
}

func lookupGeo(ctx context.Context, ip string) map[string]any {
	status, _, body, err := core.HTTPGet(ctx, fmt.Sprintf(geoAPI, ip), nil, nil)
	if err != nil || status != 200 {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(body, &out) != nil {
		return nil
	}
	return out
}

func lookupURLHaus(ctx context.Context, host string) map[string]any {
	body := []byte(url.Values{"host": []string{host}}.Encode())
	status, resp, err := core.HTTPPost(ctx, urlhausHost, "application/x-www-form-urlencoded", body)
	if err != nil || status != 200 {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(resp, &out) != nil {
		return nil
	}
	return out
}

func lookupThreatFox(ctx context.Context, ioc string) map[string]any {
	body, _ := json.Marshal(map[string]any{"query": "search_ioc", "search_term": ioc})
	status, resp, err := core.HTTPPost(ctx, threatfox, "application/json", body)
	if err != nil || status != 200 {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(resp, &out) != nil {
		return nil
	}
	return out
}

func score(i *intel) {
	if uh, ok := i.URLHaus["urls"]; ok {
		if urls, ok := uh.([]any); ok && len(urls) > 0 {
			i.Score += 40
			i.Reasons = append(i.Reasons, fmt.Sprintf("URLhaus: %d URLs", len(urls)))
		}
	}
	if tf, ok := i.ThreatFox["data"].([]any); ok && len(tf) > 0 {
		i.Score += 60
		i.Reasons = append(i.Reasons, fmt.Sprintf("ThreatFox: %d matches", len(tf)))
	}
}

func Enrich(ctx context.Context, iocs []string) *core.Result {
	r := core.NewResult("intel", strings.Join(iocs, ","))
	entries := make([]intel, 0, len(iocs))

	type task struct {
		idx  int
		ioc  string
		kind core.IOCType
	}
	tasks := make([]task, 0, len(iocs))
	for idx, raw := range iocs {
		t := task{idx: idx, ioc: strings.TrimSpace(raw), kind: core.Classify(raw)}
		if t.ioc == "" || t.kind == core.IOCUnknown {
			continue
		}
		tasks = append(tasks, t)
	}
	entries = make([]intel, len(tasks))

	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, t := range tasks {
		wg.Add(1)
		go func(i int, t task) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			e := intel{IOC: t.ioc, Kind: string(t.kind)}
			switch t.kind {
			case core.IOCIPv4:
				e.Geo = lookupGeo(ctx, t.ioc)
				e.ThreatFox = lookupThreatFox(ctx, t.ioc)
			case core.IOCDomain:
				e.URLHaus = lookupURLHaus(ctx, t.ioc)
				e.ThreatFox = lookupThreatFox(ctx, t.ioc)
			case core.IOCURL:
				e.ThreatFox = lookupThreatFox(ctx, t.ioc)
			case core.IOCMD5, core.IOCSHA1, core.IOCSHA256:
				e.ThreatFox = lookupThreatFox(ctx, t.ioc)
			}
			score(&e)
			entries[i] = e
		}(i, t)
	}
	wg.Wait()

	for _, e := range entries {
		if e.Score >= 60 {
			r.Add(core.Finding{
				Tool: "intel", Severity: core.SevCrit,
				Title:  "Malicious IOC: " + e.IOC,
				Detail: strings.Join(e.Reasons, ", "),
				Evidence: map[string]any{"kind": e.Kind, "score": e.Score},
			})
		} else if e.Score >= 40 {
			r.Add(core.Finding{
				Tool: "intel", Severity: core.SevHigh,
				Title:  "Suspect IOC: " + e.IOC,
				Detail: strings.Join(e.Reasons, ", "),
				Evidence: map[string]any{"kind": e.Kind, "score": e.Score},
			})
		}
	}
	r.AddExtra("entries", entries)
	r.Finish()
	return r
}
