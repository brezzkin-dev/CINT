package t02_geoint

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	core "github.com/ollie/phantomfs/internal/universe/core"
	"github.com/ollie/phantomfs/internal/universe/tools/t07_phototrace"
)

type Options struct {
	IP, Coords, Image string
}

func Run(opts Options) (*core.Result, error) {
	r := core.NewResult("geoint", first(opts.IP, opts.Coords, opts.Image))
	ctx := context.Background()

	if opts.IP != "" {
		url := fmt.Sprintf("http://ip-api.com/json/%s", opts.IP)
		if status, _, body, err := core.HTTPGet(ctx, url, nil); err == nil && status == 200 {
			var out map[string]any
			if json.Unmarshal(body, &out) == nil {
				r.AddExtra("ip_geo", out)
			}
		}
	}
	if opts.Coords != "" {
		var lat, lon float64
		fmt.Sscanf(strings.ReplaceAll(opts.Coords, " ", ""), "%f,%f", &lat, &lon)
		r.AddExtra("lat", lat)
		r.AddExtra("lon", lon)
		revURL := fmt.Sprintf("https://nominatim.openstreetmap.org/reverse?format=json&lat=%f&lon=%f", lat, lon)
		if status, _, body, err := core.HTTPGet(ctx, revURL, map[string]string{"User-Agent": "Universe/1.0"}); err == nil && status == 200 {
			var out map[string]any
			if json.Unmarshal(body, &out) == nil {
				r.AddExtra("reverse", out)
			}
		}
	}
	if opts.Image != "" {
		data, err := os.ReadFile(opts.Image)
		if err != nil {
			return nil, err
		}
		exif := t07_phototrace.ParseEXIF(data)
		if exif != nil {
			r.AddExtra("exif", exif)
			if gps, ok := exif["GPSDecimal"]; ok {
				r.AddExtra("gps", gps)
			}
		}
	}
	r.Finish()
	return r, nil
}

func first(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
