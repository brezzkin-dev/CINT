package t18_evidencevault

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	core "github.com/ollie/phantomfs/internal/universe/core"
)

type Entry struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	OrigName  string `json:"orig_name"`
	Size      int64  `json:"size"`
	MD5       string `json:"md5"`
	SHA256    string `json:"sha256"`
	MTime     string `json:"mtime"`
	AddedAt   string `json:"added_at"`
	BlobPath  string `json:"blob_path"`
	PrevHash  string `json:"prev_hash"`
	ThisHash  string `json:"this_hash"`
}

type Manifest struct {
	Created string  `json:"created"`
	Entries []Entry `json:"entries"`
}

func vaultPaths(root string) (manifest, blobs string) {
	return filepath.Join(root, "manifest.json"), filepath.Join(root, "blobs")
}

func Init(vault string) (*core.Result, error) {
	r := core.NewResult("evidencevault-init", vault)
	if err := os.MkdirAll(filepath.Join(vault, "blobs"), 0755); err != nil {
		return r, err
	}
	m := Manifest{Created: time.Now().UTC().Format(time.RFC3339), Entries: []Entry{}}
	if err := saveManifest(vault, &m); err != nil {
		return r, err
	}
	r.AddExtra("vault", vault)
	r.Add(core.Finding{Tool: "evidencevault", Severity: core.SevInfo, Title: "Vault initialized"})
	r.Finish()
	return r, nil
}

func Add(vault, file, label string) (*core.Result, error) {
	r := core.NewResult("evidencevault-add", file)
	m, err := loadManifest(vault)
	if err != nil {
		return r, fmt.Errorf("load manifest: %w (run init first?)", err)
	}
	stat, err := os.Stat(file)
	if err != nil {
		return r, err
	}
	f, err := os.Open(file)
	if err != nil {
		return r, err
	}
	defer f.Close()

	h256 := sha256.New()
	hmd5 := md5.New()
	w := io.MultiWriter(h256, hmd5)
	if _, err := io.Copy(w, f); err != nil {
		return r, err
	}
	sha := hex.EncodeToString(h256.Sum(nil))
	md := hex.EncodeToString(hmd5.Sum(nil))

	// Content-addressed blob
	blobDir := filepath.Join(vault, "blobs", sha[:2])
	os.MkdirAll(blobDir, 0755)
	blobPath := filepath.Join(blobDir, sha)
	if _, err := os.Stat(blobPath); os.IsNotExist(err) {
		src, _ := os.Open(file)
		dst, err := os.Create(blobPath)
		if err != nil {
			return r, err
		}
		io.Copy(dst, src)
		src.Close()
		dst.Close()
	}

	prev := ""
	if len(m.Entries) > 0 {
		prev = m.Entries[len(m.Entries)-1].ThisHash
	}
	entry := Entry{
		ID: fmt.Sprintf("%04d", len(m.Entries)+1), Label: label,
		OrigName: filepath.Base(file), Size: stat.Size(),
		MD5: md, SHA256: sha, MTime: stat.ModTime().UTC().Format(time.RFC3339),
		AddedAt: time.Now().UTC().Format(time.RFC3339),
		BlobPath: blobPath, PrevHash: prev,
	}
	entry.ThisHash = chainHash(entry)
	m.Entries = append(m.Entries, entry)
	if err := saveManifest(vault, m); err != nil {
		return r, err
	}
	r.AddExtra("entry", entry)
	r.Add(core.Finding{Tool: "evidencevault", Severity: core.SevInfo,
		Title: "Evidence added", Detail: entry.ID + " " + entry.SHA256[:16]})
	r.Finish()
	return r, nil
}

func Verify(vault string) (*core.Result, error) {
	r := core.NewResult("evidencevault-verify", vault)
	m, err := loadManifest(vault)
	if err != nil {
		return r, err
	}
	ok, broken := 0, 0
	prev := ""
	for i, e := range m.Entries {
		expected := chainHash(Entry{
			ID: e.ID, Label: e.Label, OrigName: e.OrigName, Size: e.Size,
			MD5: e.MD5, SHA256: e.SHA256, MTime: e.MTime, AddedAt: e.AddedAt,
			BlobPath: e.BlobPath, PrevHash: prev,
		})
		if e.PrevHash != prev || e.ThisHash != expected {
			broken++
			r.Add(core.Finding{Tool: "evidencevault", Severity: core.SevCrit,
				Title: fmt.Sprintf("Chain break at entry %d (%s)", i+1, e.ID),
				Detail: "hash mismatch — possible tampering"})
		} else {
			ok++
		}
		// Verify blob exists and matches
		if data, err := os.ReadFile(e.BlobPath); err == nil {
			got := hex.EncodeToString(sha256Sum(data))
			if got != e.SHA256 {
				broken++
				r.Add(core.Finding{Tool: "evidencevault", Severity: core.SevCrit,
					Title: "Blob hash mismatch: " + e.ID})
			}
		} else {
			broken++
			r.Add(core.Finding{Tool: "evidencevault", Severity: core.SevHigh,
				Title: "Missing blob: " + e.ID, Detail: e.BlobPath})
		}
		prev = e.ThisHash
	}
	r.AddExtra("verified_ok", ok)
	r.AddExtra("broken", broken)
	r.AddExtra("total", len(m.Entries))
	if broken == 0 {
		r.Add(core.Finding{Tool: "evidencevault", Severity: core.SevInfo, Title: "Chain intact"})
	}
	r.Finish()
	return r, nil
}

func List(vault string) (*core.Result, error) {
	r := core.NewResult("evidencevault-list", vault)
	m, err := loadManifest(vault)
	if err != nil {
		return r, err
	}
	r.AddExtra("created", m.Created)
	r.AddExtra("entries", m.Entries)
	r.AddExtra("count", len(m.Entries))
	r.Finish()
	return r, nil
}

func chainHash(e Entry) string {
	// SHA256(prev || id || label || name || size || md5 || sha256 || mtime || added || blob)
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%d|%s|%s|%s|%s|%s",
		e.PrevHash, e.ID, e.Label, e.OrigName, e.Size, e.MD5, e.SHA256, e.MTime, e.AddedAt, e.BlobPath)
	return hex.EncodeToString(h.Sum(nil))
}

func loadManifest(vault string) (*Manifest, error) {
	path, _ := vaultPaths(vault)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func saveManifest(vault string, m *Manifest) error {
	path, _ := vaultPaths(vault)
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

func sha256Sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
