package t12_darkintel

import (
	"context"
	"encoding/json"
	"strings"

	core "github.com/ollie/phantomfs/internal/universe/core"
)

func Run(ioc, feed string) (*core.Result, error) {
	r := core.NewResult("darkintel", first(ioc, feed))
	ctx := context.Background()

	if feed == "feodo" || feed == "" && ioc == "" {
		status, _, body, err := core.HTTPGet(ctx, "https://feodotracker.abuse.ch/downloads/ipblocklist.json", nil)
		if err == nil && status == 200 {
			var entries []map[string]any
			if json.Unmarshal(body, &entries) == nil {
				r.AddExtra("feodo_count", len(entries))
				if len(entries) > 20 {
					entries = entries[:20]
				}
				r.AddExtra("feodo_sample", entries)
			}
		}
	}
	if ioc != "" {
		// URLhaus host lookup
		body := []byte("host=" + ioc)
		status, resp, err := core.HTTPPost(ctx, "https://urlhaus-api.abuse.ch/v1/host/", "application/x-www-form-urlencoded", body, nil)
		if err == nil && status == 200 {
			var out map[string]any
			if json.Unmarshal(resp, &out) == nil {
				r.AddExtra("urlhaus", out)
				if q, ok := out["query_status"].(string); ok && q == "ok" {
					r.Add(core.Finding{Tool: "darkintel", Severity: core.SevHigh, Title: "URLhaus hit: " + ioc})
				}
			}
		}
	}
	if feed == "urlhaus" {
		status, _, body, err := core.HTTPGet(ctx, "https://urlhaus.abuse.ch/downloads/csv_recent/", nil)
		if err == nil && status == 200 {
			lines := strings.Split(string(body), "\n")
			r.AddExtra("urlhaus_recent_lines", len(lines))
		}
	}
	r.Finish()
	return r, nil
}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
