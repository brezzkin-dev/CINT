package phish

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/ollie/phantomfs/internal/cyber/core"
)

var suspiciousTLDs = []string{
	".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".cc",
	".click", ".download", ".loan", ".work", ".gdn",
}

var brandWords = []string{
	"paypal", "apple", "microsoft", "google", "amazon", "facebook",
	"instagram", "netflix", "dhl", "fedex", "ups", "steam", "binance",
	"coinbase", "metamask", "revolut", "hsbc", "chase",
}

func hasNonASCII(s string) bool {
	for _, c := range s {
		if c > unicode.MaxASCII {
			return true
		}
	}
	return false
}

func damerauLevenshtein(a, b string) int {
	a, b = strings.ToLower(a), strings.ToLower(b)
	if a == b {
		return 0
	}
	la, lb := len(a), len(b)
	d := make([][]int, la+1)
	for i := range d {
		d[i] = make([]int, lb+1)
		d[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		d[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			d[i][j] = min3(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				if alt := d[i-2][j-2] + 1; alt < d[i][j] {
					d[i][j] = alt
				}
			}
		}
	}
	return d[la][lb]
}

func min3(a, b, c int) int {
	if a <= b && a <= c {
		return a
	}
	if b <= c {
		return b
	}
	return c
}

func typosquatScore(host string) (int, string) {
	base := host
	if i := strings.Index(host, "."); i > 0 {
		base = host[:i]
	}
	best, brand := 99, ""
	for _, b := range brandWords {
		if d := damerauLevenshtein(base, b); d < best {
			best, brand = d, b
		}
	}
	if best == 0 {
		return 0, ""
	}
	if best <= 2 {
		return 40, fmt.Sprintf("typosquat of %s (distance %d)", brand, best)
	}
	return 0, ""
}

func lexicalScore(u *url.URL) (int, []string) {
	var score int
	var reasons []string
	host := strings.ToLower(u.Hostname())
	if hasNonASCII(host) {
		score += 30
		reasons = append(reasons, "non-ASCII hostname")
	}
	if strings.Contains(host, "xn--") {
		score += 25
		reasons = append(reasons, "punycode")
	}
	for _, tld := range suspiciousTLDs {
		if strings.HasSuffix(host, tld) {
			score += 15
			reasons = append(reasons, "suspicious TLD "+tld)
			break
		}
	}
	for _, b := range brandWords {
		if strings.Contains(host, b) && !(host == b+".com" || host == "www."+b+".com") {
			score += 30
			reasons = append(reasons, "brand in host: "+b)
			break
		}
	}
	if s, r := typosquatScore(host); s > 0 {
		score += s
		reasons = append(reasons, r)
	}
	if len(host) > 30 {
		score += 10
		reasons = append(reasons, "long hostname")
	}
	if strings.Count(host, ".") > 4 {
		score += 15
		reasons = append(reasons, "excessive subdomains")
	}
	if strings.Contains(u.Path, "@") {
		score += 20
		reasons = append(reasons, "@ in path")
	}
	return score, reasons
}

func redirectChain(ctx context.Context, raw string) ([]string, string) {
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	chain := []string{raw}
	cur := raw
	for i := 0; i < 8; i++ {
		req, err := http.NewRequestWithContext(ctx, "GET", cur, nil)
		if err != nil {
			break
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Obsidian/2.0)")
		resp, err := client.Do(req)
		if err != nil {
			return chain, ""
		}
		loc := resp.Header.Get("Location")
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if loc == "" {
			return chain, string(body)
		}
		next, err := url.Parse(loc)
		if err != nil {
			return chain, string(body)
		}
		curURL, _ := url.Parse(cur)
		cur = curURL.ResolveReference(next).String()
		chain = append(chain, cur)
	}
	return chain, ""
}

func pageContentScore(body string) (int, []string) {
	var score int
	var reasons []string
	lc := strings.ToLower(body)
	if strings.Contains(lc, `type="password"`) || strings.Contains(lc, "type=password") {
		score += 20
		reasons = append(reasons, "password field present")
	}
	for _, kw := range []string{"verify your account", "suspended", "click here to confirm", "urgent action"} {
		if strings.Contains(lc, kw) {
			score += 10
			reasons = append(reasons, "urgency language")
			break
		}
	}
	return score, reasons
}

func checkDNS(ctx context.Context, domain string, r *core.Result) {
	addrs, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil || len(addrs) == 0 {
		r.AddExtra("mx_records", 0)
	}
	txts, _ := net.DefaultResolver.LookupTXT(ctx, domain)
	var spf, dmarc bool
	for _, t := range txts {
		if strings.HasPrefix(t, "v=spf1") {
			spf = true
		}
	}
	dmarcs, _ := net.DefaultResolver.LookupTXT(ctx, "_dmarc."+domain)
	for _, t := range dmarcs {
		if strings.HasPrefix(t, "v=DMARC1") {
			dmarc = true
		}
	}
	r.AddExtra("spf", spf)
	r.AddExtra("dmarc", dmarc)
	if !spf {
		r.Add(core.Finding{Tool: "phish", Severity: core.SevMed, Title: "SPF missing", Detail: domain})
	}
	if !dmarc {
		r.Add(core.Finding{Tool: "phish", Severity: core.SevMed, Title: "DMARC missing", Detail: domain})
	}
}

func Analyze(ctx context.Context, raw string) *core.Result {
	r := core.NewResult("phish", raw)
	if !strings.HasPrefix(raw, "http") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		r.Add(core.Finding{Tool: "phish", Severity: core.SevHigh, Title: "invalid URL", Detail: err.Error()})
		r.Finish()
		return r
	}
	score, reasons := lexicalScore(u)
	r.AddExtra("host", u.Hostname())
	r.AddExtra("score", score)
	r.AddExtra("reasons", reasons)

	chain, finalBody := redirectChain(ctx, raw)
	r.AddExtra("redirect_chain", chain)
	if len(chain) > 1 {
		r.AddExtra("redirect_count", len(chain)-1)
		r.Add(core.Finding{Tool: "phish", Severity: core.SevMed,
			Title:  fmt.Sprintf("URL redirects through %d hops", len(chain)-1),
			Detail: strings.Join(chain, " → ")})
	}
	if finalBody != "" {
		if cs, cr := pageContentScore(finalBody); cs > 0 {
			score += cs
			reasons = append(reasons, cr...)
			r.AddExtra("page_signals", cr)
		}
	}
	checkDNS(ctx, u.Hostname(), r)
	if score >= 60 {
		r.Add(core.Finding{Tool: "phish", Severity: core.SevCrit,
			Title: "high phishing likelihood", Detail: strings.Join(reasons, ", ")})
	} else if score >= 30 {
		r.Add(core.Finding{Tool: "phish", Severity: core.SevHigh,
			Title: "suspicious", Detail: strings.Join(reasons, ", ")})
	}
	r.Finish()
	return r
}
