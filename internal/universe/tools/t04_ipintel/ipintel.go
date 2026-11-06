package t04_ipintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	core "github.com/ollie/phantomfs/internal/universe/core"
)

func Run(ip string) (*core.Result, error) {
	r := core.NewResult("ipintel", ip)
	ctx := context.Background()
	if names, err := net.LookupAddr(ip); err == nil {
		r.AddExtra("ptr", names)
	}
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,region,city,lat,lon,isp,org,as,query", ip)
	if status, _, body, err := core.HTTPGet(ctx, url, nil); err == nil && status == 200 {
		var out map[string]any
		if json.Unmarshal(body, &out) == nil {
			r.AddExtra("geo", out)
			if cc, ok := out["countryCode"].(string); ok && cc != "" {
				r.Add(core.Finding{Tool: "ipintel", Severity: core.SevInfo,
					Title:  "Geo: " + fmt.Sprint(out["city"]) + ", " + fmt.Sprint(out["country"]),
					Detail: fmt.Sprint(out["as"])})
			}
		}
	}
	r.Finish()
	return r, nil
}
