package recover

import (
	"os"
	"path/filepath"

	"github.com/ollie/phantomfs/internal/core"
	"github.com/ollie/phantomfs/internal/scan"
)

func Reconstruct(root string) (int, error) {
	entries, err := scan.Walk(scan.Options{Root: root})
	if err != nil {
		return 0, err
	}
	seen := map[string]bool{}
	for _, e := range entries {
		dir := filepath.Dir(e.Path)
		if !seen[dir] {
			seen[dir] = true
			if err := os.MkdirAll(dir, 0755); err != nil {
				core.Warnf("mkdir %s: %v", dir, err)
			}
		}
	}
	return len(seen), nil
}
