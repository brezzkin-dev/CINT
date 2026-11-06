package cint_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/brezzkin-dev/CINT/internal/chunk"
	"github.com/brezzkin-dev/CINT/internal/hash"
	"github.com/brezzkin-dev/CINT/internal/index"
	"github.com/brezzkin-dev/CINT/internal/magic"
	"github.com/brezzkin-dev/CINT/internal/modules/dup"
	"github.com/brezzkin-dev/CINT/internal/modules/tree"
	"github.com/brezzkin-dev/CINT/internal/scan"
)

// TestEndToEndPhantomfs exercises the full phantomfs pipeline:
// build tree → walk → hash → dup find → index save → index load → diff.
func TestEndToEndPhantomfs(t *testing.T) {
	root := t.TempDir()

	// 1. Build a tree with duplicates + unique files + hidden files
	files := map[string][]byte{
		"a.txt":       []byte("hello world duplicate content"),
		"b.txt":       []byte("hello world duplicate content"), // dup of a
		"c.txt":       []byte("unique content"),
		"sub/d.txt":   []byte("hello world duplicate content"), // dup of a
		"sub/e.txt":   []byte("another unique"),
		".hidden.txt": []byte("hidden"),
		"sub/.inner":  []byte("nested hidden"),
	}
	for name, content := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, content, 0644); err != nil {
			t.Fatal(err)
		}
	}

	// 2. Walk
	entries, err := scan.WalkContext(context.Background(), scan.Options{Root: root, Workers: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 7 {
		t.Fatalf("walk found %d entries, want 7+", len(entries))
	}

	// 3. Dup detection
	groups := dup.Find(entries)
	if len(groups) < 1 {
		t.Fatalf("expected at least 1 dup group, got %d", len(groups))
	}
	if len(groups[0].Paths) < 3 {
		t.Fatalf("expected 3 paths in dup group, got %d", len(groups[0].Paths))
	}

	// 4. Index save/load round-trip
	snapPath := filepath.Join(root, "snap.phfs")
	if err := index.Save(snapPath, entries); err != nil {
		t.Fatal(err)
	}
	loaded, err := index.Load(snapPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != len(entries) {
		t.Fatalf("index round-trip lost entries: %d != %d", len(loaded), len(entries))
	}

	// 5. Modify the tree, then diff
	if err := os.WriteFile(filepath.Join(root, "new.txt"), []byte("brand new"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "c.txt")); err != nil {
		t.Fatal(err)
	}
	newEntries, err := scan.Walk(scan.Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	changes := index.Diff(loaded, newEntries)
	var added, deleted int
	for _, c := range changes {
		switch c.Kind {
		case "added":
			added++
		case "deleted":
			deleted++
		}
	}
	if added < 1 {
		t.Fatalf("expected added file, got %d", added)
	}
	if deleted < 1 {
		t.Fatalf("expected deleted file, got %d", deleted)
	}
}

// TestHashDupInteraction proves the parallel hasher produces consistent
// results used by the dup finder.
func TestHashDupInteraction(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"x", "y", "z"} {
		os.WriteFile(filepath.Join(root, name), []byte("same content"), 0644)
	}
	os.WriteFile(filepath.Join(root, "unique"), []byte("different content"), 0644)

	entries, err := scan.Walk(scan.Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	hashes := hash.HashParallel(context.Background(), entries)
	if len(hashes) < 4 {
		t.Fatalf("hashed %d files, want 4", len(hashes))
	}
	xh := hashes[filepath.Join(root, "x")]
	yh := hashes[filepath.Join(root, "y")]
	zh := hashes[filepath.Join(root, "z")]
	uh := hashes[filepath.Join(root, "unique")]
	if xh != yh || yh != zh {
		t.Fatal("duplicate files should hash equal")
	}
	if xh == uh {
		t.Fatal("unique file should not hash equal to duplicates")
	}
}

// TestChunkDedupInteraction proves FastCDC produces consistent chunks
// across identical files.
func TestChunkDedupInteraction(t *testing.T) {
	content := make([]byte, 100_000)
	for i := range content {
		content[i] = byte(i * 13)
	}
	f := chunk.NewFastCDC(512, 4096, 65536, 42)

	cutsA := f.Cut(content)
	cutsB := f.Cut(content)
	if len(cutsA) != len(cutsB) {
		t.Fatalf("chunk counts differ: %d vs %d", len(cutsA), len(cutsB))
	}
	for i := range cutsA {
		if cutsA[i] != cutsB[i] {
			t.Fatalf("chunk %d boundary differs", i)
		}
	}
	if cutsA[len(cutsA)-1] != len(content) {
		t.Fatalf("last boundary %d != %d", cutsA[len(cutsA)-1], len(content))
	}
}

// TestMagicClassification proves magic detection differentiates file types.
func TestMagicClassification(t *testing.T) {
	root := t.TempDir()

	// Real PNG header + padding
	pngData := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 100)...)
	os.WriteFile(filepath.Join(root, "img.png"), pngData, 0644)

	// Real PDF header + padding
	pdfData := append([]byte("%PDF-1.7\n"), make([]byte, 100)...)
	os.WriteFile(filepath.Join(root, "doc.pdf"), pdfData, 0644)

	// Unknown format
	os.WriteFile(filepath.Join(root, "unknown.bin"), []byte("abcdefghij"), 0644)

	cases := map[string]string{
		"img.png":     "image/png",
		"doc.pdf":     "application/pdf",
		"unknown.bin": "",
	}
	for name, wantMime := range cases {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		mime, _, ok := magic.Detect(data)
		if wantMime == "" && ok {
			t.Fatalf("%s: expected no detection", name)
		}
		if wantMime != "" && (!ok || mime != wantMime) {
			t.Fatalf("%s: got %q ok=%v, want %q", name, mime, ok, wantMime)
		}
	}
}

// TestTreeRenderOverWalk proves the tree builder consumes walker output
// and produces valid hierarchical structure.
func TestTreeRenderOverWalk(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"a.txt":     "1",
		"sub/b.txt": "2",
		"sub/c.txt": "3",
	}
	for name, content := range files {
		p := filepath.Join(root, name)
		os.MkdirAll(filepath.Dir(p), 0755)
		os.WriteFile(p, []byte(content), 0644)
	}

	entries, err := scan.Walk(scan.Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	treeRoot := tree.Build(entries)
	if treeRoot == nil {
		t.Fatal("nil tree")
	}
	if _, ok := treeRoot.Children["a.txt"]; !ok {
		t.Fatal("a.txt missing from tree")
	}
	sub, ok := treeRoot.Children["sub"]
	if !ok {
		t.Fatal("sub missing from tree")
	}
	if _, ok := sub.Children["b.txt"]; !ok {
		t.Fatal("sub/b.txt missing")
	}
}

func TestWalkCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	entries, _ := scan.WalkContext(ctx, scan.Options{Root: t.TempDir()})
	_ = entries
}
