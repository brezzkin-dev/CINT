package t14_geoarchive

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	core "github.com/ollie/phantomfs/internal/universe/core"
)

func Run(coords, place string) (*core.Result, error) {
	r := core.NewResult("geoarchive", first(coords, place))
	ctx := context.Background()
	var lat, lon float64

	if coords != "" {
		fmt.Sscanf(strings.ReplaceAll(coords, " ", ""), "%f,%f", &lat, &lon)
	} else if place != "" {
		url := fmt.Sprintf("https://nominatim.openstreetmap.org/search?format=json&q=%s", place)
		status, _, body, err := core.HTTPGet(ctx, url, map[string]string{"User-Agent": "Universe-OSINT/1.0"})
		if err != nil || status != 200 {
			return r, fmt.Errorf("geocode failed")
		}
		var out []map[string]any
		if json.Unmarshal(body, &out) == nil && len(out) > 0 {
			fmt.Sscanf(fmt.Sprint(out[0]["lat"]), "%f", &lat)
			fmt.Sscanf(fmt.Sprint(out[0]["lon"]), "%f", &lon)
			r.AddExtra("geocode", out[0])
		}
	}
	if lat == 0 && lon == 0 {
		return r, fmt.Errorf("could not determine coordinates")
	}
	r.AddExtra("lat", lat)
	r.AddExtra("lon", lon)

	revURL := fmt.Sprintf("https://nominatim.openstreetmap.org/reverse?format=json&lat=%f&lon=%f", lat, lon)
	if status, _, body, err := core.HTTPGet(ctx, revURL, map[string]string{"User-Agent": "Universe-OSINT/1.0"}); err == nil && status == 200 {
		var out map[string]any
		if json.Unmarshal(body, &out) == nil {
			r.AddExtra("reverse", out)
		}
	}
	wikiURL := fmt.Sprintf("https://en.wikipedia.org/w/api.php?action=query&list=geosearch&gscoord=%f|%f&gsradius=10000&gslimit=10&format=json", lat, lon)
	if status, _, body, err := core.HTTPGet(ctx, wikiURL, nil); err == nil && status == 200 {
		var out map[string]any
		if json.Unmarshal(body, &out) == nil {
			r.AddExtra("wikipedia", out)
		}
	}
	r.Finish()
	return r, nil
}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
