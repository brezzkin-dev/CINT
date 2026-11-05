package t17_binarycore

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"debug/elf"
	"debug/pe"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	core "github.com/ollie/phantomfs/internal/universe/core"
)

var reStr = regexp.MustCompile(`[\x20-\x7e]{4,}`)

var suspiciousAPIs = map[string]core.Severity{
	"VirtualAllocEx": core.SevHigh, "WriteProcessMemory": core.SevHigh,
	"CreateRemoteThread": core.SevCrit, "NtCreateThreadEx": core.SevHigh,
	"SetWindowsHookExA": core.SevMed, "SetWindowsHookExW": core.SevMed,
	"GetAsyncKeyState": core.SevHigh, "URLDownloadToFileA": core.SevHigh,
	"URLDownloadToFileW": core.SevHigh, "InternetOpenUrlA": core.SevHigh,
	"WinExec": core.SevHigh, "ShellExecuteA": core.SevMed, "ShellExecuteW": core.SevMed,
	"CryptEncrypt": core.SevMed, "CryptDecrypt": core.SevMed,
	"AdjustTokenPrivileges": core.SevHigh, "OpenProcessToken": core.SevMed,
	"IsDebuggerPresent": core.SevLow, "CheckRemoteDebuggerPresent": core.SevLow,
}

type SectionInfo struct {
	Name    string  `json:"name"`
	Size    uint64  `json:"size"`
	Entropy float64 `json:"entropy"`
}

func Run(path string) (*core.Result, error) {
	r := core.NewResult("binarycore", path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r.AddExtra("size", len(data))
	r.AddExtra("md5", hex.EncodeToString(md5Sum(data)))
	r.AddExtra("sha1", hex.EncodeToString(sha1Sum(data)))
	r.AddExtra("sha256", hex.EncodeToString(sha256Sum(data)))
	r.AddExtra("entropy_overall", roundf(entropy(data), 3))

	if len(data) >= 2 && data[0] == 'M' && data[1] == 'Z' {
		analyzePE(path, data, r)
	} else if len(data) >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		analyzeELF(path, data, r)
	} else {
		r.AddExtra("format", "unknown")
		r.AddExtra("magic", detectMagic(data))
	}

	// Embedded strings / URLs
	matches := reStr.FindAll(data, 500)
	urls := []string{}
	seen := map[string]bool{}
	for _, m := range matches {
		s := string(m)
		if (strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")) && !seen[s] {
			seen[s] = true
			urls = append(urls, s)
			if len(urls) >= 30 {
				break
			}
		}
	}
	if len(urls) > 0 {
		r.AddExtra("urls", urls)
		r.Add(core.Finding{Tool: "binarycore", Severity: core.SevMed, Title: "Embedded URLs", Detail: strings.Join(urls[:min(5, len(urls))], "; ")})
	}
	r.Finish()
	return r, nil
}

func analyzePE(path string, data []byte, r *core.Result) {
	f, err := pe.Open(path)
	if err != nil {
		r.AddExtra("format", "pe-raw")
		return
	}
	defer f.Close()
	r.AddExtra("format", "pe")
	r.AddExtra("arch", peArch(f.Machine))
	r.AddExtra("compile_time_unix", f.FileHeader.TimeDateStamp)
	r.AddExtra("characteristics", f.FileHeader.Characteristics)

	var secs []SectionInfo
	for _, s := range f.Sections {
		raw, _ := s.Data()
		ent := roundf(entropy(raw), 3)
		secs = append(secs, SectionInfo{Name: s.Name, Size: uint64(len(raw)), Entropy: ent})
		if len(raw) > 512 && ent > 7.2 {
			r.Add(core.Finding{Tool: "binarycore", Severity: core.SevHigh,
				Title: "Packed section: " + s.Name, Detail: fmt.Sprintf("entropy %.3f", ent)})
		}
	}
	r.AddExtra("sections", secs)

	// Overlay
	var lastEnd int64
	for _, s := range f.Sections {
		end := int64(s.Offset) + int64(s.Size)
		if end > lastEnd {
			lastEnd = end
		}
	}
	if int64(len(data)) > lastEnd {
		overlay := int64(len(data)) - lastEnd
		r.AddExtra("overlay_bytes", overlay)
		sev := core.SevMed
		if overlay > 1<<20 {
			sev = core.SevHigh
		}
		r.Add(core.Finding{Tool: "binarycore", Severity: sev, Title: "PE overlay detected",
			Evidence: map[string]any{"bytes": overlay}})
	}

	if imports, err := f.ImportedSymbols(); err == nil {
		r.AddExtra("import_count", len(imports))
		var hits []string
		for _, imp := range imports {
			if sev, ok := suspiciousAPIs[imp]; ok {
				hits = append(hits, imp)
				r.Add(core.Finding{Tool: "binarycore", Severity: sev, Title: "Suspicious import: " + imp})
			}
		}
		r.AddExtra("suspicious_imports", hits)
	}
	if libs, err := f.ImportedLibraries(); err == nil {
		r.AddExtra("dlls", libs)
	}
}

func analyzeELF(path string, data []byte, r *core.Result) {
	f, err := elf.Open(path)
	if err != nil {
		r.AddExtra("format", "elf-raw")
		return
	}
	defer f.Close()
	r.AddExtra("format", "elf")
	r.AddExtra("arch", f.Machine.String())
	r.AddExtra("type", f.Type.String())
	var secs []SectionInfo
	for _, s := range f.Sections {
		raw, _ := s.Data()
		secs = append(secs, SectionInfo{Name: s.Name, Size: uint64(len(raw)), Entropy: roundf(entropy(raw), 3)})
	}
	r.AddExtra("sections", secs)
	_ = data
	_ = filepath.Base
}

func detectMagic(data []byte) string {
	if len(data) < 4 {
		return "too-small"
	}
	switch {
	case data[0] == 0x1f && data[1] == 0x8b:
		return "gzip"
	case data[0] == 'P' && data[1] == 'K':
		return "zip/jar"
	case data[0] == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G':
		return "png"
	case data[0] == 0xff && data[1] == 0xd8:
		return "jpeg"
	case string(data[:4]) == "%PDF":
		return "pdf"
	case data[0] == 0x7f && data[1] == 'E':
		return "elf"
	case data[0] == 'M' && data[1] == 'Z':
		return "pe"
	}
	return "unknown"
}

func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func roundf(f float64, p int) float64 {
	m := math.Pow(10, float64(p))
	return math.Round(f*m) / m
}
func peArch(m uint16) string {
	switch m {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x86_64"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	}
	return "unknown"
}
func md5Sum(b []byte) []byte    { h := md5.Sum(b); return h[:] }
func sha1Sum(b []byte) []byte   { h := sha1.Sum(b); return h[:] }
func sha256Sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
