package scan

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ollie/phantomfs/internal/core"
)

// Options controls a directory walk. Workers == 0 means runtime.NumCPU().
type Options struct {
	Root     string
	MaxDepth int
	MinSize  int64
	Ignore   []string
	Workers  int
}

// Walk is the serial entry point. It uses one worker.
func Walk(opts Options) ([]core.FileEntry, error) {
	opts.Workers = 1
	return WalkContext(context.Background(), opts)
}

// WalkContext walks root in parallel using a worker pool of opts.Workers.
// It returns all entries in arbitrary order. Cancelling ctx aborts early,
// returning entries collected so far.
func WalkContext(ctx context.Context, opts Options) ([]core.FileEntry, error) {
	root, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, err
	}
	workers := opts.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers < 1 {
		workers = 1
	}

	jobs := make(chan string, workers*4)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var out []core.FileEntry

	// pending counts unprocessed directories + entries still in flight.
	var pending int32 = 1
	var emptyOnce sync.Once
	empty := make(chan struct{})
	dec := func() {
		if atomic.AddInt32(&pending, -1) == 0 {
			emptyOnce.Do(func() { close(empty) })
		}
	}
	inc := func() { atomic.AddInt32(&pending, 1) }

	walkDir := func(dir string) {
		items, err := os.ReadDir(dir)
		if err != nil {
			core.Warnf("readdir %s: %v", dir, err)
			return
		}
		for _, de := range items {
			select {
			case <-ctx.Done():
				return
			default:
			}
			p := filepath.Join(dir, de.Name())
			info, ierr := de.Info()
			if ierr != nil {
				continue
			}
			rel, rerr := filepath.Rel(root, p)
			if rerr != nil {
				continue
			}
			if opts.MaxDepth > 0 {
				depth := strings.Count(rel, string(filepath.Separator)) + 1
				if depth > opts.MaxDepth {
					continue
				}
			}
			ignored := false
			for _, pat := range opts.Ignore {
				if ok, _ := filepath.Match(pat, info.Name()); ok {
					ignored = true
					break
				}
			}
			if ignored {
				continue
			}
			if !info.IsDir() && info.Size() < opts.MinSize {
				continue
			}

			e := core.FileEntry{
				Path:      p,
				RelPath:   rel,
				Size:      info.Size(),
				Mode:      uint32(info.Mode()),
				ModTime:   info.ModTime(),
				IsDir:     info.IsDir(),
				IsSymlink: info.Mode()&os.ModeSymlink != 0,
				Ext:       strings.ToLower(filepath.Ext(p)),
			}
			ext := core.ExtInfoOf(info)
			e.Inode = ext.Inode
			e.Nlink = ext.Nlink
			e.Blocks = ext.Blocks
			if !info.IsDir() && ext.Blocks > 0 {
				e.Sparse = info.Size() > int64(ext.Blocks)*512
			}
			if strings.HasPrefix(info.Name(), ".") && info.Name() != "." && info.Name() != ".." {
				e.IsHidden = true
			}
			if !info.IsDir() {
				f, ferr := os.Open(p)
				if ferr == nil {
					f.Close()
					e.Readable = true
				}
			}
			mu.Lock()
			out = append(out, e)
			mu.Unlock()

			if de.IsDir() {
				inc()
				select {
				case jobs <- p:
				case <-ctx.Done():
					dec()
				}
			}
		}
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for dir := range jobs {
				walkDir(dir)
				dec()
			}
		}()
	}

	select {
	case jobs <- root:
	case <-ctx.Done():
		dec()
	}

	go func() {
		<-empty
		close(jobs)
	}()

	wg.Wait()
	return out, nil
}
