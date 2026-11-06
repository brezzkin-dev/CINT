// Package wsa — Website Security Auditing.
package wsa

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ollie/phantomfs/internal/cyber/core"
)

var secHeaders = map[string]struct {
	Sev core.Severity
	Msg string
}{
	"Strict-Transport-Security": {core.SevHigh, "HSTS missing — SSL-strip feasible"},
	"Content-Security-Policy":   {core.SevMed, "CSP missing — XSS mitigation weak"},
	"X-Frame-Options":           {core.SevMed, "clickjacking possible"},
	"X-Content-Type-Options":    {core.SevLow, "MIME sniffing possible"},
	"Referrer-Policy":           {core.SevLow, "referrer leakage"},
	"Permissions-Policy":        {core.SevLow, "browser feature access unrestricted"},
}

var commonPaths = []string{
	"/.git/HEAD", "/.git/config", "/.env", "/server-status",
	"/phpinfo.php", "/admin", "/.DS_Store", "/backup.zip",
	"/swagger.json", "/openapi.json", "/actuator/health",
}

var techSigs = map[string][]string{
	"nginx":      {"Server: nginx"},
	"apache":     {"Server: Apache"},
	"cloudflare": {"Server: cloudflare", "cf-ray"},
	"iis":        {"Server: Microsoft-IIS"},
	"php":        {"X-Powered-By: PHP"},
	"aspnet":     {"X-AspNet-Version", "X-Powered-By: ASP.NET"},
	"express":    {"X-Powered-By: Express"},
	"wordpress":  {"wp-content", "wp-includes"},
	"drupal":     {"Drupal.settings", "X-Generator: Drupal"},
	"react":      {"__NEXT_DATA__", "data-reactroot"},
}

func auditTLS(host string) *tls.ConnectionState {
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: host}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", host+":443", cfg)
	if err != nil {
		return nil
	}
	defer conn.Close()
	state := conn.ConnectionState()
	return &state
}

type Options struct {
	Inject   bool
	Takeover bool
}

func Audit(ctx context.Context, target string, opts Options) *core.Result {
	r := core.NewResult("wsa", target)

	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}
	u, err := url.Parse(target)
	if err != nil {
		r.Add(core.Finding{Tool: "wsa", Severity: core.SevHigh, Title: "invalid URL", Detail: err.Error()})
		r.Finish()
		return r
	}

	status, headers, body, err := core.HTTPGet(ctx, target, nil, nil)
	if err != nil {
		r.Add(core.Finding{Tool: "wsa", Severity: core.SevHigh, Title: "fetch failed", Detail: err.Error()})
		r.Finish()
		return r
	}
	r.AddExtra("status", status)
	r.AddExtra("final_url", target)
	r.AddExtra("body_size", len(body))

	lcHeaders := map[string]string{}
	for k, v := range headers {
		lcHeaders[strings.ToLower(k)] = strings.Join(v, ", ")
	}

	for name, cfg := range secHeaders {
		if _, ok := lcHeaders[strings.ToLower(name)]; !ok {
			r.Add(core.Finding{
				Tool: "wsa", Severity: cfg.Sev,
				Title:  "Missing header: " + name,
				Detail: cfg.Msg,
			})
		}
	}

	if csp, ok := lcHeaders["content-security-policy"]; ok {
		if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			r.Add(core.Finding{
				Tool: "wsa", Severity: core.SevMed,
				Title:  "Weak CSP",
				Detail: "contains 'unsafe-inline' or 'unsafe-eval'",
			})
		}
	}

	for _, cookie := range headers["Set-Cookie"] {
		lc := strings.ToLower(cookie)
		if !strings.Contains(lc, "secure") && u.Scheme == "https" {
			r.Add(core.Finding{Tool: "wsa", Severity: core.SevMed, Title: "Cookie missing Secure"})
		}
		if !strings.Contains(lc, "httponly") {
			r.Add(core.Finding{Tool: "wsa", Severity: core.SevMed, Title: "Cookie missing HttpOnly"})
		}
		if !strings.Contains(lc, "samesite") {
			r.Add(core.Finding{Tool: "wsa", Severity: core.SevLow, Title: "Cookie missing SameSite"})
		}
	}

	if state := auditTLS(u.Hostname()); state != nil {
		r.AddExtra("tls_version", tlsVersionString(state.Version))
		r.AddExtra("cipher_suite", tls.CipherSuiteName(state.CipherSuite))
		if state.Version < tls.VersionTLS12 {
			r.Add(core.Finding{Tool: "wsa", Severity: core.SevHigh, Title: "Weak TLS",
				Detail: tlsVersionString(state.Version)})
		}
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			r.AddExtra("cert_subject", cert.Subject.String())
			r.AddExtra("cert_issuer", cert.Issuer.String())
			r.AddExtra("cert_expires", cert.NotAfter.Format(time.RFC3339))
			if time.Now().After(cert.NotAfter) {
				r.Add(core.Finding{Tool: "wsa", Severity: core.SevCrit, Title: "Certificate expired"})
			}
		}
	}

	bodyStr := string(body)
	var tech []string
	for name, sigs := range techSigs {
		for _, sig := range sigs {
			if strings.Contains(bodyStr, sig) || strings.Contains(strings.ToLower(fmtHeaders(headers)), strings.ToLower(sig)) {
				tech = append(tech, name)
				break
			}
		}
	}
	sort.Strings(tech)
	r.AddExtra("tech", tech)

	base := u.Scheme + "://" + u.Host
	seen := map[string]bool{}
	for _, p := range commonPaths {
		full := base + p
		if seen[full] {
			continue
		}
		seen[full] = true
		st, _, _, _ := core.HTTPGet(ctx, full, nil, nil)
		if st == 200 {
			r.Add(core.Finding{
				Tool: "wsa", Severity: core.SevHigh,
				Title:  "Sensitive path reachable: " + p,
				Detail: full,
			})
		}
	}
	r.Finish()
	return r
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return "unknown"
}

func fmtHeaders(h map[string][]string) string {
	var b strings.Builder
	for k, v := range h {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(strings.Join(v, ", "))
		b.WriteString("\n")
	}
	return b.String()
}
