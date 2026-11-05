package t06_mailtrace

import (
	"context"
	"crypto/md5"
	"fmt"
	"net"
	"strings"

	core "github.com/ollie/phantomfs/internal/universe/core"
)

func Run(email string) (*core.Result, error) {
	r := core.NewResult("mailtrace", email)
	ctx := context.Background()
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid email")
	}
	domain := parts[1]
	r.AddExtra("local", parts[0])
	r.AddExtra("domain", domain)

	if mx, err := net.LookupMX(domain); err == nil {
		var mxs []string
		for _, m := range mx {
			mxs = append(mxs, m.Host)
		}
		r.AddExtra("mx", mxs)
	}
	if txt, err := net.LookupTXT(domain); err == nil {
		for _, t := range txt {
			if strings.HasPrefix(t, "v=spf1") {
				r.AddExtra("spf", t)
			}
		}
	}
	if dmarc, err := net.LookupTXT("_dmarc." + domain); err == nil {
		for _, t := range dmarc {
			if strings.HasPrefix(t, "v=DMARC1") {
				r.AddExtra("dmarc", t)
			}
		}
	}
	// Gravatar
	hash := fmt.Sprintf("%x", md5.Sum([]byte(strings.ToLower(strings.TrimSpace(email)))))
	gravURL := "https://www.gravatar.com/avatar/" + hash + "?d=404"
	if status, _, _, err := core.HTTPGet(ctx, gravURL, nil); err == nil && status == 200 {
		r.AddExtra("gravatar", true)
		r.Add(core.Finding{Tool: "mailtrace", Severity: core.SevInfo, Title: "Gravatar present"})
	} else {
		r.AddExtra("gravatar", false)
	}
	r.Finish()
	return r, nil
}
