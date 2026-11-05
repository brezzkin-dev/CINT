package t01_osintcore

import (
	"strings"

	core "github.com/ollie/phantomfs/internal/universe/core"
	"github.com/ollie/phantomfs/internal/universe/tools/t03_domaintrace"
	"github.com/ollie/phantomfs/internal/universe/tools/t04_ipintel"
	"github.com/ollie/phantomfs/internal/universe/tools/t05_userfinder"
	"github.com/ollie/phantomfs/internal/universe/tools/t06_mailtrace"
)

func Run(target string) (*core.Result, error) {
	r := core.NewResult("osintcore", target)
	kind := core.Classify(target)
	r.AddExtra("classified_as", string(kind))

	switch kind {
	case core.IOCIPv4, core.IOCIPv6:
		sub, err := t04_ipintel.Run(target)
		if err == nil {
			r.Findings = append(r.Findings, sub.Findings...)
			r.AddExtra("ipintel", sub.Extra)
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
		sub, err := t03_domaintrace.Run(host)
		if err == nil {
			r.Findings = append(r.Findings, sub.Findings...)
			r.AddExtra("domaintrace", sub.Extra)
		}
	case core.IOCEmail:
		sub, err := t06_mailtrace.Run(target)
		if err == nil {
			r.Findings = append(r.Findings, sub.Findings...)
			r.AddExtra("mailtrace", sub.Extra)
		}
	default:
		sub, err := t05_userfinder.Run(target)
		if err == nil {
			r.Findings = append(r.Findings, sub.Findings...)
			r.AddExtra("userfinder", sub.Extra)
		}
	}
	r.Finish()
	return r, nil
}
