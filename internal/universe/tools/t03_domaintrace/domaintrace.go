package t03_domaintrace

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	core "github.com/ollie/phantomfs/internal/universe/core"
)

func Run(domain string) (*core.Result, error) {
	r := core.NewResult("domaintrace", domain)
	ctx := context.Background()

	if ips, err := net.LookupHost(domain); err == nil {
		r.AddExtra("a_records", ips)
	}
	if mx, err := net.LookupMX(domain); err == nil {
		var mxs []string
		for _, m := range mx {
			mxs = append(mxs, m.Host)
		}
		r.AddExtra("mx", mxs)
	}
	if ns, err := net.LookupNS(domain); err == nil {
		var nss []string
		for _, n := range ns {
			nss = append(nss, n.Host)
		}
		r.AddExtra("ns", nss)
	}
	if txt, err := net.LookupTXT(domain); err == nil {
		r.AddExtra("txt", txt)
	}

	// crt.sh
	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain)
	if status, _, body, err := core.HTTPGet(ctx, url, nil); err == nil && status == 200 {
		var certs []map[string]any
		if json.Unmarshal(body, &certs) == nil {
			r.AddExtra("ct_count", len(certs))
			names := map[string]bool{}
			for _, c := range certs {
				if nv, ok := c["name_value"].(string); ok {
					for _, line := range strings.Split(nv, "\n") {
						line = strings.TrimSpace(line)
						if line != "" {
							names[line] = true
						}
					}
				}
			}
			var list []string
			for n := range names {
				list = append(list, n)
				if len(list) >= 50 {
					break
				}
			}
			r.AddExtra("ct_names", list)
		}
	}
	r.Finish()
	return r, nil
}
