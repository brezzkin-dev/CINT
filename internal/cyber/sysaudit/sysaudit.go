// Package sysaudit — System Security Auditing.
package sysaudit

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ollie/phantomfs/internal/cyber/core"
)

func findSetuid(r *core.Result, root string) {
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		m := info.Mode()
		if m&os.ModeSetuid != 0 {
			r.Add(core.Finding{Tool: "sysaudit", Severity: core.SevHigh,
				Title: "SUID binary", Detail: p, Evidence: map[string]any{"mode": m.String()}})
		}
		if m&os.ModeSetgid != 0 {
			r.Add(core.Finding{Tool: "sysaudit", Severity: core.SevMed,
				Title: "SGID binary", Detail: p})
		}
		if m.Perm()&0002 != 0 {
			r.Add(core.Finding{Tool: "sysaudit", Severity: core.SevMed,
				Title: "world-writable", Detail: p})
		}
		return nil
	})
}

func auditPasswd(r *core.Result) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(parts[2])
		if uid == 0 && parts[0] != "root" {
			r.Add(core.Finding{Tool: "sysaudit", Severity: core.SevCrit,
				Title: "Non-root UID 0", Detail: parts[0]})
		}
	}
}

func auditShadow(r *core.Result) {
	f, err := os.Open("/etc/shadow")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 2 {
			continue
		}
		if parts[1] == "" {
			r.Add(core.Finding{Tool: "sysaudit", Severity: core.SevCrit,
				Title: "Empty password", Detail: parts[0]})
		}
		if strings.HasPrefix(parts[1], "!") || strings.HasPrefix(parts[1], "*") {
			continue
		}
		if len(parts[1]) < 13 {
			r.Add(core.Finding{Tool: "sysaudit", Severity: core.SevMed,
				Title: "Weak hash scheme", Detail: parts[0]})
		}
	}
}

func auditSSH(r *core.Result) {
	f, err := os.Open("/etc/ssh/sshd_config")
	if err != nil {
		return
	}
	defer f.Close()
	checks := map[string]struct {
		Want  string
		Sev   core.Severity
		Label string
	}{
		"PermitRootLogin":        {"no", core.SevHigh, "root SSH login"},
		"PasswordAuthentication": {"no", core.SevMed, "password auth (prefer keys)"},
		"PermitEmptyPasswords":   {"no", core.SevCrit, "empty passwords"},
		"X11Forwarding":          {"no", core.SevLow, "X11 forwarding"},
		"MaxAuthTries":           {"3", core.SevLow, "too many auth tries"},
		"Protocol":               {"2", core.SevLow, "SSH protocol"},
	}
	found := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		found[fields[0]] = fields[1]
	}
	for k, cfg := range checks {
		v, ok := found[k]
		if !ok {
			r.Add(core.Finding{Tool: "sysaudit", Severity: cfg.Sev,
				Title: "SSH: " + k + " unset", Detail: "should be " + cfg.Want})
			continue
		}
		if v != cfg.Want {
			r.Add(core.Finding{Tool: "sysaudit", Severity: cfg.Sev,
				Title: "SSH: " + k + " = " + v, Detail: cfg.Label})
		}
	}
}

func auditSysctl(r *core.Result) {
	checks := []struct {
		Path string
		Want string
		Sev  core.Severity
		Desc string
	}{
		{"/proc/sys/kernel/randomize_va_space", "2", core.SevHigh, "ASLR disabled or partial"},
		{"/proc/sys/net/ipv4/ip_forward", "0", core.SevMed, "IP forwarding enabled (router mode)"},
		{"/proc/sys/net/ipv4/conf/all/accept_redirects", "0", core.SevLow, "ICMP redirects accepted"},
		{"/proc/sys/kernel/dmesg_restrict", "1", core.SevLow, "dmesg readable by all"},
		{"/proc/sys/kernel/kptr_restrict", "1", core.SevLow, "kernel pointers exposed"},
	}
	for _, c := range checks {
		b, err := os.ReadFile(c.Path)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(b)) != c.Want {
			r.Add(core.Finding{Tool: "sysaudit", Severity: c.Sev,
				Title: "sysctl: " + filepath.Base(c.Path),
				Detail: c.Desc,
				Evidence: map[string]any{"got": strings.TrimSpace(string(b)), "want": c.Want}})
		}
	}
}

func auditPorts(r *core.Result) {
	for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Scan()
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 4 {
				continue
			}
			state := fields[3]
			if state != "0A" {
				continue
			}
			parts := strings.Split(fields[1], ":")
			if len(parts) != 2 {
				continue
			}
			port, _ := strconv.ParseInt(parts[1], 16, 32)
			local := strings.Split(fields[1], ":")[0]
			if local == "00000000" || local == "00000000000000000000000000000000" {
				sev := core.SevMed
				if port == 3306 || port == 5432 || port == 6379 || port == 27017 {
					sev = core.SevHigh
				}
				r.Add(core.Finding{Tool: "sysaudit", Severity: sev,
					Title: "Listening on all interfaces: " + strconv.Itoa(int(port))})
			}
		}
		f.Close()
	}
}

func Audit(root string) *core.Result {
	r := core.NewResult("sysaudit", root)
	findSetuid(r, root)
	auditPasswd(r)
	auditShadow(r)
	auditSSH(r)
	auditSysctl(r)
	auditPorts(r)
	r.Finish()
	return r
}
