package t25_geocrypt

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	core "github.com/ollie/phantomfs/internal/universe/core"
	t07 "github.com/ollie/phantomfs/internal/universe/tools/t07_phototrace"
)

type Options struct {
	Coords string
	Image  string
	From   string
	To     string
	When   string
}

func Run(opts Options) (*core.Result, error) {
	r := core.NewResult("geocrypt", firstNonEmpty(opts.Coords, opts.Image, opts.From))
	ctx := context.Background()

	var lat, lon float64
	haveCoord := false

	if opts.Coords != "" {
		if la, lo, ok := parseCoords(opts.Coords); ok {
			lat, lon, haveCoord = la, lo, true
			r.AddExtra("coords", map[string]float64{"lat": la, "lng": lo})
		}
	}
	if opts.Image != "" {
		if elat, elng, ok := extractImageGPS(opts.Image); ok {
			r.AddExtra("exif_gps", map[string]float64{"lat": elat, "lng": elng})
			if !haveCoord {
				lat, lon, haveCoord = elat, elng, true
			}
			r.Add(core.Finding{Tool: "geocrypt", Severity: core.SevMed,
				Title: "GPS found in EXIF", Detail: fmt.Sprintf("%.6f,%.6f", elat, elng)})
		}
	}
	if !haveCoord {
		return r, fmt.Errorf("no coordinates (need -coords or -image with GPS)")
	}

	if opts.From != "" && opts.To != "" {
		la1, lo1, ok1 := parseCoords(opts.From)
		la2, lo2, ok2 := parseCoords(opts.To)
		if ok1 && ok2 {
			d := haversine(la1, lo1, la2, lo2)
			b := bearing(la1, lo1, la2, lo2)
			mid := midpoint(la1, lo1, la2, lo2)
			r.AddExtra("distance_km", roundf(d, 3))
			r.AddExtra("bearing_deg", roundf(b, 2))
			r.AddExtra("midpoint", map[string]float64{"lat": roundf(mid[0], 6), "lng": roundf(mid[1], 6)})
			r.Add(core.Finding{Tool: "geocrypt", Severity: core.SevInfo,
				Title: "Great-circle route", Detail: fmt.Sprintf("%.2f km, bearing %.1f°", d, b)})
		}
	}

	utmZone := int(math.Floor((lon+180)/6)) + 1
	r.AddExtra("utm_zone", fmt.Sprintf("%d%s", utmZone, utmBand(lat)))

	when := time.Now().UTC()
	if opts.When != "" {
		if t, err := time.Parse(time.RFC3339, opts.When); err == nil {
			when = t.UTC()
		}
	}
	sunAz, sunEl := sunPosition(lat, lon, when)
	r.AddExtra("sun", map[string]any{
		"at": when.Format(time.RFC3339), "azimuth": roundf(sunAz, 2),
		"elevation": roundf(sunEl, 2), "is_daytime": sunEl > 0,
	})

	if addr := reverseGeocode(ctx, lat, lon); addr != "" {
		r.AddExtra("address", addr)
	}
	if tz := lookupTimezone(ctx, lat, lon); tz != "" {
		r.AddExtra("timezone", tz)
	}
	if place := lookupPlace(ctx, lat, lon); place != nil {
		r.AddExtra("place", place)
	}
	r.Finish()
	return r, nil
}

func parseCoords(s string) (float64, float64, bool) {
	s = strings.ReplaceAll(s, " ", "")
	parts := strings.SplitN(s, ",", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	var lat, lon float64
	if _, err := fmt.Sscanf(parts[0], "%f", &lat); err != nil {
		return 0, 0, false
	}
	if _, err := fmt.Sscanf(parts[1], "%f", &lon); err != nil {
		return 0, 0, false
	}
	if lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		return 0, 0, false
	}
	return lat, lon, true
}

func haversine(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371.0088
	p1, p2 := lat1*math.Pi/180, lat2*math.Pi/180
	dp, dl := (lat2-lat1)*math.Pi/180, (lon2-lon1)*math.Pi/180
	a := math.Sin(dp/2)*math.Sin(dp/2) + math.Cos(p1)*math.Cos(p2)*math.Sin(dl/2)*math.Sin(dl/2)
	return R * 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}

func bearing(lat1, lon1, lat2, lon2 float64) float64 {
	p1, p2 := lat1*math.Pi/180, lat2*math.Pi/180
	dl := (lon2 - lon1) * math.Pi / 180
	y := math.Sin(dl) * math.Cos(p2)
	x := math.Cos(p1)*math.Sin(p2) - math.Sin(p1)*math.Cos(p2)*math.Cos(dl)
	return math.Mod(math.Atan2(y, x)*180/math.Pi+360, 360)
}

func midpoint(lat1, lon1, lat2, lon2 float64) [2]float64 {
	p1, lo1 := lat1*math.Pi/180, lon1*math.Pi/180
	p2, lo2 := lat2*math.Pi/180, lon2*math.Pi/180
	bx := math.Cos(p2) * math.Cos(lo2-lo1)
	by := math.Cos(p2) * math.Sin(lo2-lo1)
	pm := math.Atan2(math.Sin(p1)+math.Sin(p2), math.Sqrt((math.Cos(p1)+bx)*(math.Cos(p1)+bx)+by*by))
	lom := lo1 + math.Atan2(by, math.Cos(p1)+bx)
	return [2]float64{pm * 180 / math.Pi, lom * 180 / math.Pi}
}

func sunPosition(lat, lon float64, when time.Time) (float64, float64) {
	jd := float64(when.Unix())/86400.0 + 2440587.5
	d := jd - 2451545.0
	L := math.Mod(280.460+0.9856474*d, 360)
	g := math.Mod(357.528+0.9856003*d, 360)
	lambda := L + 1.915*math.Sin(g*math.Pi/180) + 0.020*math.Sin(2*g*math.Pi/180)
	eps := 23.439 - 0.0000004*d
	alpha := math.Atan2(math.Cos(eps*math.Pi/180)*math.Sin(lambda*math.Pi/180), math.Cos(lambda*math.Pi/180)) * 180 / math.Pi
	delta := math.Asin(math.Sin(eps*math.Pi/180)*math.Sin(lambda*math.Pi/180)) * 180 / math.Pi
	gmst := math.Mod(280.46061837+360.98564736629*d, 360)
	lst := math.Mod(gmst+lon, 360)
	H := math.Mod(lst-alpha+180, 360) - 180
	h := math.Asin(math.Sin(lat*math.Pi/180)*math.Sin(delta*math.Pi/180) +
		math.Cos(lat*math.Pi/180)*math.Cos(delta*math.Pi/180)*math.Cos(H*math.Pi/180))
	elevation := h * 180 / math.Pi
	az := math.Atan2(-math.Sin(H*math.Pi/180),
		math.Tan(delta*math.Pi/180)*math.Cos(lat*math.Pi/180)-math.Sin(lat*math.Pi/180)*math.Cos(H*math.Pi/180))
	return math.Mod(az*180/math.Pi+360, 360), elevation
}

func utmBand(lat float64) string {
	const bands = "CDEFGHJKLMNPQRSTUVWXX"
	if lat < -80 || lat > 84 {
		return "?"
	}
	idx := int(math.Floor((lat + 80) / 8))
	if idx < 0 {
		idx = 0
	}
	if idx >= len(bands) {
		idx = len(bands) - 1
	}
	return string(bands[idx])
}

func extractImageGPS(path string) (float64, float64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false
	}
	exif := t07.ParseEXIF(data)
	if exif == nil {
		return 0, 0, false
	}
	// Flexible GPS extraction
	if gps, ok := exif["GPSDecimal"].([]float64); ok && len(gps) == 2 {
		return gps[0], gps[1], true
	}
	if lat, ok1 := toFloat(exif["GPSLatitude"]); ok1 {
		if lon, ok2 := toFloat(exif["GPSLongitude"]); ok2 {
			if ref, ok := exif["GPSLatitudeRef"].(string); ok && strings.ToUpper(ref) == "S" {
				lat = -lat
			}
			if ref, ok := exif["GPSLongitudeRef"].(string); ok && strings.ToUpper(ref) == "W" {
				lon = -lon
			}
			return lat, lon, true
		}
	}
	return 0, 0, false
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case string:
		var f float64
		if _, err := fmt.Sscanf(x, "%f", &f); err == nil {
			return f, true
		}
	}
	return 0, false
}

func reverseGeocode(ctx context.Context, lat, lon float64) string {
	url := fmt.Sprintf("https://nominatim.openstreetmap.org/reverse?format=json&lat=%f&lon=%f", lat, lon)
	status, _, body, err := core.HTTPGet(ctx, url, map[string]string{"User-Agent": "Universe-OSINT/1.0"})
	if err != nil || status != 200 {
		return ""
	}
	var out map[string]any
	if json.Unmarshal(body, &out) != nil {
		return ""
	}
	if s, ok := out["display_name"].(string); ok {
		return s
	}
	return ""
}

func lookupTimezone(ctx context.Context, lat, lon float64) string {
	url := fmt.Sprintf("https://api.open-meteo.com/v1/forecast?latitude=%f&longitude=%f&current_weather=true", lat, lon)
	status, _, body, err := core.HTTPGet(ctx, url, nil)
	if err != nil || status != 200 {
		return ""
	}
	var out map[string]any
	if json.Unmarshal(body, &out) != nil {
		return ""
	}
	if tz, ok := out["timezone"].(string); ok {
		return tz
	}
	return ""
}

func lookupPlace(ctx context.Context, lat, lon float64) map[string]any {
	url := fmt.Sprintf("https://nominatim.openstreetmap.org/reverse?format=json&lat=%f&lon=%f&zoom=14", lat, lon)
	status, _, body, err := core.HTTPGet(ctx, url, map[string]string{"User-Agent": "Universe-OSINT/1.0"})
	if err != nil || status != 200 {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(body, &out) != nil {
		return nil
	}
	if addr, ok := out["address"].(map[string]any); ok {
		return addr
	}
	return nil
}

func roundf(f float64, p int) float64 {
	m := math.Pow(10, float64(p))
	return math.Round(f*m) / m
}
func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
