package t10_metatrack

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	core "github.com/ollie/phantomfs/internal/universe/core"
	"github.com/ollie/phantomfs/internal/universe/tools/t07_phototrace"
)

func Run(path string) (*core.Result, error) {
	r := core.NewResult("metatrack", path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	stat, _ := os.Stat(path)
	r.AddExtra("size", len(data))
	r.AddExtra("ext", strings.ToLower(filepath.Ext(path)))
	if stat != nil {
		r.AddExtra("mod_time", stat.ModTime().UTC().Format("2006-01-02T15:04:05Z"))
	}
	r.AddExtra("md5", fmt.Sprintf("%x", md5.Sum(data)))
	r.AddExtra("sha1", fmt.Sprintf("%x", sha1.Sum(data)))
	r.AddExtra("sha256", fmt.Sprintf("%x", sha256.Sum256(data)))

	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".jpg" || ext == ".jpeg" || ext == ".png" || ext == ".gif" {
		if exif := t07_phototrace.ParseEXIF(data); exif != nil {
			r.AddExtra("exif", exif)
		}
	}
	// PDF crude
	if strings.HasPrefix(string(data[:min(8, len(data))]), "%PDF") {
		r.AddExtra("format", "pdf")
		if i := strings.Index(string(data), "/Author"); i > 0 {
			r.AddExtra("pdf_has_author_field", true)
		}
	}
	r.Finish()
	return r, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
