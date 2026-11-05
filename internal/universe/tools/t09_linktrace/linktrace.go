package t09_linktrace

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	core "github.com/ollie/phantomfs/internal/universe/core"
)

func Run(raw string) (*core.Result, error) {
	r := core.NewResult("linktrace", raw)
	ctx := context.Background()
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	chain := []string{raw}
	cur := raw
	for i := 0; i < 10; i++ {
		req, err := http.NewRequestWithContext(ctx, "GET", cur, nil)
		if err != nil {
			break
		}
		req.Header.Set("User-Agent", "Universe/1.0")
		resp, err := client.Do(req)
		if err != nil {
			r.AddExtra("error", err.Error())
			break
		}
		loc := resp.Header.Get("Location")
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		r.AddExtra(fmt.Sprintf("hop_%d_status", i), resp.StatusCode)
		if loc == "" {
			break
		}
		next, err := url.Parse(loc)
		if err != nil {
			break
		}
		curURL, _ := url.Parse(cur)
		cur = curURL.ResolveReference(next).String()
		chain = append(chain, cur)
	}
	r.AddExtra("redirect_chain", chain)
	r.AddExtra("hops", len(chain)-1)
	if len(chain) > 1 {
		r.Add(core.Finding{Tool: "linktrace", Severity: core.SevMed,
			Title: fmt.Sprintf("%d redirect hops", len(chain)-1),
			Detail: strings.Join(chain, " → ")})
	}
	r.Finish()
	return r, nil
}
