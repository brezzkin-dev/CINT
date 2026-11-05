package t05_userfinder

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	core "github.com/ollie/phantomfs/internal/universe/core"
)

var platforms = []struct {
	Name string
	URL  string
}{
	{"GitHub", "https://github.com/%s"},
	{"Twitter", "https://twitter.com/%s"},
	{"Reddit", "https://www.reddit.com/user/%s"},
	{"Instagram", "https://www.instagram.com/%s"},
	{"LinkedIn", "https://www.linkedin.com/in/%s"},
	{"YouTube", "https://www.youtube.com/@%s"},
	{"TikTok", "https://www.tiktok.com/@%s"},
	{"Pinterest", "https://www.pinterest.com/%s"},
	{"Twitch", "https://www.twitch.tv/%s"},
	{"Medium", "https://medium.com/@%s"},
	{"HackerNews", "https://news.ycombinator.com/user?id=%s"},
	{"Keybase", "https://keybase.io/%s"},
	{"GitLab", "https://gitlab.com/%s"},
	{"Bitbucket", "https://bitbucket.org/%s"},
	{"Steam", "https://steamcommunity.com/id/%s"},
	{"DeviantArt", "https://www.deviantart.com/%s"},
	{"Flickr", "https://www.flickr.com/people/%s"},
	{"SoundCloud", "https://soundcloud.com/%s"},
	{"Vimeo", "https://vimeo.com/%s"},
	{"About.me", "https://about.me/%s"},
}

func Run(user string) (*core.Result, error) {
	r := core.NewResult("userfinder", user)
	ctx := context.Background()
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	var mu sync.Mutex
	var found []map[string]any
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, p := range platforms {
		wg.Add(1)
		go func(name, tmpl string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			url := fmt.Sprintf(tmpl, user)
			req, _ := http.NewRequestWithContext(ctx, "HEAD", url, nil)
			req.Header.Set("User-Agent", "Universe/1.0")
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()
			if resp.StatusCode != 404 && resp.StatusCode < 500 {
				mu.Lock()
				found = append(found, map[string]any{"platform": name, "url": url, "status": resp.StatusCode})
				r.Add(core.Finding{Tool: "userfinder", Severity: core.SevInfo,
					Title: "Found on " + name, Detail: url})
				mu.Unlock()
			}
		}(p.Name, p.URL)
	}
	wg.Wait()
	r.AddExtra("found", found)
	r.AddExtra("found_count", len(found))
	r.Finish()
	return r, nil
}
