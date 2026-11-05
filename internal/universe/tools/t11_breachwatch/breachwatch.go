package t11_breachwatch

import (
	"context"
	"crypto/sha1"
	"fmt"
	"strings"

	core "github.com/ollie/phantomfs/internal/universe/core"
)

func Run(email, domain string) (*core.Result, error) {
	target := email
	if target == "" {
		target = domain
	}
	r := core.NewResult("breachwatch", target)
	ctx := context.Background()

	if email != "" {
		// HIBP password range is for passwords; for email we note limitation
		h := fmt.Sprintf("%X", sha1.Sum([]byte(strings.ToLower(email))))
		prefix, suffix := h[:5], h[5:]
		url := "https://api.pwnedpasswords.com/range/" + prefix
		status, _, body, err := core.HTTPGet(ctx, url, nil)
		if err == nil && status == 200 {
			found := false
			for _, line := range strings.Split(string(body), "\n") {
				parts := strings.Split(strings.TrimSpace(line), ":")
				if len(parts) == 2 && strings.EqualFold(parts[0], suffix) {
					found = true
					r.Add(core.Finding{Tool: "breachwatch", Severity: core.SevHigh,
						Title: "Hash appears in HIBP range", Detail: "count=" + parts[1]})
					break
				}
			}
			r.AddExtra("hibp_range_match", found)
		}
		r.AddExtra("note", "full email breach lookup needs HIBP API key; range endpoint used as proxy")
	}
	if domain != "" {
		url := "https://haveibeenpwned.com/api/v3/breaches"
		if status, _, body, err := core.HTTPGet(ctx, url, nil); err == nil && status == 200 {
			r.AddExtra("breach_list_bytes", len(body))
			r.AddExtra("note_domain", "fetched public breach catalog; filter client-side by domain")
		}
	}
	r.Finish()
	return r, nil
}
