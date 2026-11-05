package t15_entitylink

import (
	"net"
	"strings"

	core "github.com/ollie/phantomfs/internal/universe/core"
	"github.com/ollie/phantomfs/internal/universe/tools/t03_domaintrace"
	"github.com/ollie/phantomfs/internal/universe/tools/t04_ipintel"
	"github.com/ollie/phantomfs/internal/universe/tools/t05_userfinder"
	"github.com/ollie/phantomfs/internal/universe/tools/t06_mailtrace"
)

func Run(target string) (*core.Result, error) {
	r := core.NewResult("entitylink", target)
	target = strings.TrimSpace(target)
	entities := map[string]string{}
	var domains, ips, users, emails []string

	kind := core.Classify(target)
	switch kind {
	case core.IOCEmail:
		emails = append(emails, target)
		entities[target] = "email"
		if at := strings.LastIndex(target, "@"); at >= 0 {
			d := target[at+1:]
			domains = append(domains, d)
			entities[d] = "domain"
			users = append(users, target[:at])
			entities[target[:at]] = "username"
		}
	case core.IOCDomain, core.IOCURL:
		host := target
		if kind == core.IOCURL {
			if i := strings.Index(host, "://"); i >= 0 {
				host = host[i+3:]
			}
			if i := strings.IndexAny(host, "/:?#"); i >= 0 {
				host = host[:i]
			}
		}
		domains = append(domains, host)
		entities[host] = "domain"
	case core.IOCIPv4, core.IOCIPv6:
		ips = append(ips, target)
		entities[target] = "ip"
	default:
		users = append(users, target)
		entities[target] = "username"
	}

	for _, d := range domains {
		if resolved, err := net.LookupHost(d); err == nil {
			for _, ip := range resolved {
				entities[ip] = "ip"
				ips = append(ips, ip)
			}
		}
		if dt, err := t03_domaintrace.Run(d); err == nil {
			r.AddExtra("domaintrace:"+d, dt.Extra)
			r.Findings = append(r.Findings, dt.Findings...)
		}
	}
	seen := map[string]bool{}
	for _, ip := range ips {
		if seen[ip] {
			continue
		}
		seen[ip] = true
		if ipr, err := t04_ipintel.Run(ip); err == nil {
			r.AddExtra("ipintel:"+ip, ipr.Extra)
			r.Findings = append(r.Findings, ipr.Findings...)
		}
	}
	for _, em := range emails {
		if mr, err := t06_mailtrace.Run(em); err == nil {
			r.AddExtra("mailtrace:"+em, mr.Extra)
		}
	}
	for _, u := range users {
		if uf, err := t05_userfinder.Run(u); err == nil {
			r.AddExtra("userfinder:"+u, uf.Extra)
			r.Findings = append(r.Findings, uf.Findings...)
		}
	}

	entitiesOut := make([]map[string]string, 0, len(entities))
	for v, t := range entities {
		entitiesOut = append(entitiesOut, map[string]string{"value": v, "type": t})
	}
	r.AddExtra("entities", entitiesOut)
	r.AddExtra("entity_count", len(entities))
	r.Add(core.Finding{Tool: "entitylink", Severity: core.SevInfo,
		Title: "Entity graph built", Detail: itoa(len(entities)) + " linked entities"})
	r.Finish()
	return r, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
