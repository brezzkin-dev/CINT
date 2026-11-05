// Package asm — Attack Surface Mapping.
package asm

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ollie/phantomfs/internal/cyber/core"
)

var topPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
	1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
	8888, 9000, 9090, 9200, 11211, 27017,
}

type subdomain struct {
	Host string `json:"host"`
	IP   string `json:"ip,omitempty"`
}

type service struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Banner string `json:"banner,omitempty"`
	TLS    bool   `json:"tls,omitempty"`
}

func crtSH(ctx context.Context, domain string) []string {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	status, _, body, err := core.HTTPGet(ctx, url, nil, nil)
	if err != nil || status != 200 {
		return nil
	}
	var raw []struct {
		NameValue string `json:"name_value"`
	}
	if json.Unmarshal(body, &raw) != nil {
		return nil
	}
	set := map[string]bool{}
	for _, r := range raw {
		for _, line := range strings.Split(r.NameValue, "\n") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "*."))
			if line != "" && strings.HasSuffix(line, domain) {
				set[line] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

func resolve(host string) string {
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0]
}

func probe(host string, port int, timeout time.Duration) *service {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	conn.Write([]byte("\r\n"))
	n, _ := conn.Read(buf)
	svc := &service{Host: host, Port: port, Banner: strings.TrimSpace(string(buf[:n]))}
	if port == 443 || port == 8443 {
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
		if tc.Handshake() == nil {
			svc.TLS = true
		}
	}
	return svc
}

func scanPorts(host string) []*service {
	return scanPortsWith(host, topPorts)
}

func scanPortsWith(host string, ports []int) []*service {
	var out []*service
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for _, p := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if svc := probe(host, p, 2*time.Second); svc != nil {
				mu.Lock()
				out = append(out, svc)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	return out
}

func Map(ctx context.Context, domain string, fullPorts bool) *core.Result {
	r := core.NewResult("asm", domain)

	subs := crtSH(ctx, domain)
	r.AddExtra("subdomain_count", len(subs))

	var resolved []subdomain
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 16)
	for _, s := range subs {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ip := resolve(s); ip != "" {
				mu.Lock()
				resolved = append(resolved, subdomain{Host: s, IP: ip})
				mu.Unlock()
			}
		}(s)
	}
	wg.Wait()
	r.AddExtra("subdomains", resolved)

	ports := topPorts
	if fullPorts {
		ports = make([]int, 0, 65535)
		for i := 1; i <= 65535; i++ {
			ports = append(ports, i)
		}
	}
	apex := scanPortsWith(domain, ports)
	r.AddExtra("services", apex)
	r.AddExtra("full_ports", fullPorts)

	for _, svc := range apex {
		sev := core.SevLow
		if svc.Port == 3306 || svc.Port == 5432 || svc.Port == 6379 || svc.Port == 27017 || svc.Port == 11211 {
			sev = core.SevHigh
		} else if svc.Port == 21 || svc.Port == 23 || svc.Port == 445 {
			sev = core.SevHigh
		}
		r.Add(core.Finding{
			Tool: "asm", Severity: sev,
			Title: fmt.Sprintf("Open port %d", svc.Port),
			Detail: svc.Banner,
			Evidence: map[string]any{"host": svc.Host, "tls": svc.TLS},
		})
	}
	r.Finish()
	return r
}
