package phantomfs_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ollie/phantomfs/internal/chunk"
	"github.com/ollie/phantomfs/internal/hash"
	"github.com/ollie/phantomfs/internal/scan"
)

func TestEndToEnd(t *testing.T) {
	root := t.TempDir()

	// Build a small tree.
	files := map[string][]byte{
		"a.txt":       []byte("hello world"),
		"b.txt":       []byte("hello world"), // duplicate
		"sub/c.txt":   []byte("content"),
		".hidden.txt": []byte("x"),
	}
	for name, data := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Walk.
	entries, err := scan.WalkContext(context.Background(), scan.Options{Root: root, Workers: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 4 {
		t.Fatalf("walk found %d entries", len(entries))
	}

	// Hash in parallel.
	hashes := hash.HashParallel(context.Background(), entries)
	if len(hashes) < 3 {
		t.Fatalf("hashed %d files", len(hashes))
	}

	// a.txt and b.txt should hash equal.
	aHash := hashes[filepath.Join(root, "a.txt")]
	bHash := hashes[filepath.Join(root, "b.txt")]
	if aHash != bHash {
		t.Fatalf("duplicate files hash differently")
	}

	// FastCDC roundtrip.
	data := make([]byte, 100_000)
	for i := range data {
		data[i] = byte(i)
	}
	f := chunk.NewFastCDC(512, 4096, 65536, 42)
	cuts := f.Cut(data)
	if cuts[len(cuts)-1] != len(data) {
		t.Fatalf("cut end %d != %d", cuts[len(cuts)-1], len(data))
	}
}

func TestWalkCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before walk starts
	entries, _ := scan.WalkContext(ctx, scan.Options{Root: t.TempDir()})
	// Should return quickly, possibly empty.
	_ = entries
}
