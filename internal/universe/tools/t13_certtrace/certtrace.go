package t13_certtrace

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	core "github.com/ollie/phantomfs/internal/universe/core"
)

func Run(domain string) (*core.Result, error) {
	r := core.NewResult("certtrace", domain)
	ctx := context.Background()

	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		r.Add(core.Finding{Tool: "certtrace", Severity: core.SevLow, Title: "TLS connect failed", Detail: err.Error()})
	} else {
		defer conn.Close()
		state := conn.ConnectionState()
		r.AddExtra("tls_version", tlsVersionStr(state.Version))
		if len(state.PeerCertificates) > 0 {
			c := state.PeerCertificates[0]
			r.AddExtra("live_cert", map[string]any{
				"subject": c.Subject.String(), "issuer": c.Issuer.String(),
				"not_before": c.NotBefore.Format(time.RFC3339),
				"not_after":  c.NotAfter.Format(time.RFC3339),
				"dns_names":  c.DNSNames, "serial": c.SerialNumber.String(),
			})
			if time.Now().After(c.NotAfter) {
				r.Add(core.Finding{Tool: "certtrace", Severity: core.SevCrit, Title: "Live certificate expired"})
			} else if time.Now().Add(30 * 24 * time.Hour).After(c.NotAfter) {
				r.Add(core.Finding{Tool: "certtrace", Severity: core.SevMed, Title: "Certificate expires within 30 days"})
			}
		}
	}

	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain)
	if status, _, body, err := core.HTTPGet(ctx, url, nil); err == nil && status == 200 {
		var certs []map[string]any
		if json.Unmarshal(body, &certs) == nil {
			r.AddExtra("ct_history_count", len(certs))
			issuers := map[string]int{}
			for _, c := range certs {
				if in, ok := c["issuer_name"].(string); ok {
					issuers[in]++
				}
			}
			r.AddExtra("ct_issuers", issuers)
		}
	}
	r.Finish()
	return r, nil
}

func tlsVersionStr(v uint16) string {
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

var _ = strings.TrimSpace
