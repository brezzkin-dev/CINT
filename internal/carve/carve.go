// Package carve extracts embedded files (JPEG, PNG, GIF, PDF, ZIP) from
// raw byte streams using signature/end-marker pairs. Every read is
// bounds-checked; malformed input produces no output rather than panics.
package carve

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// Carved describes a successfully extracted file.
type Carved struct {
	Type   string `json:"type"`
	Offset int64  `json:"offset"`
	Size   int64  `json:"size"`
	Path   string `json:"path"`
}

type sigPair struct {
	Type  string
	Start []byte
	End   []byte
	Ext   string
}

var pairs = []sigPair{
	{"JPEG", []byte("\xff\xd8\xff"), []byte("\xff\xd9"), "jpg"},
	{"PNG", []byte("\x89PNG\r\n\x1a\n"), []byte("IEND\xaeB`\x82"), "png"},
	{"GIF", []byte("GIF8"), []byte("\x00\x3b"), "gif"},
	{"PDF", []byte("%PDF-"), []byte("%%EOF"), "pdf"},
	{"ZIP", []byte("PK\x03\x04"), []byte("PK\x05\x06"), "zip"},
}

// Carve scans data for known file signatures and writes matches into
// outDir. Returns the carved files and the first error encountered while
// writing (scanning itself never errors).
func Carve(data []byte, outDir string) ([]Carved, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return nil, err
	}
	n := len(data)
	var carved []Carved
	var firstErr error

	for _, p := range pairs {
		idx := 0
		for {
			relStart := bytes.Index(data[idx:], p.Start)
			if relStart < 0 {
				break
			}
			start := idx + relStart
			searchFrom := start + len(p.Start)
			if searchFrom >= n {
				break
			}
			relEnd := bytes.Index(data[searchFrom:], p.End)
			if relEnd < 0 {
				break
			}
			end := searchFrom + relEnd + len(p.End)
			if end > n || end-start < len(p.Start)+len(p.End) {
				break
			}
			name := filepath.Join(outDir, fmt.Sprintf("%s_%08x.%s", p.Type, start, p.Ext))
			if werr := os.WriteFile(name, data[start:end], 0644); werr != nil {
				if firstErr == nil {
					firstErr = werr
				}
				idx = end
				continue
			}
			carved = append(carved, Carved{
				Type:   p.Type,
				Offset: int64(start),
				Size:   int64(end - start),
				Path:   name,
			})
			idx = end
		}
	}
	return carved, firstErr
}

// CarveFile reads path fully and carves it into outDir.
func CarveFile(path, outDir string) ([]Carved, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Carve(data, outDir)
}
