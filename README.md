# PHANTOMFS 2.0

Filesystem intelligence engine. Pure Go, stdlib only, no AI/ML.
Same public surface as 2.0, hardened internals.

## What's real here
- **Streaming XXH64** — 1 MiB read buffer, constant memory, matches reference vectors.
- **FastCDC** — normalized content-defined chunking (two masks), real resync property.
- **Parallel walker** — worker pool, atomic pending, close-on-empty, ctx-aware.
- **Panic recovery** — every command wrapped by `core.SafeRun`.
- **Bounds-checked carve** — no panic on truncated signatures.
- **Real tests** — XXH64 vectors, FastCDC properties, bloom FP rate, carve edges, end-to-end.

## Build
```
go build -o phantomfs ./cmd/phantomfs
go test ./...
go test -bench ./...
```

## Quick reference
```
phantomfs scan     -root /data -workers 8 -json
phantomfs dupes    -root .
phantomfs dedup    -root . -avg 4096 -json
phantomfs bloom    -root . -check-file suspect.bin
phantomfs hash     -file big.bin
phantomfs magic    -file unknown.bin
phantomfs carve    -file disk.img -out carved/
phantomfs snapshot -root . -out before.phfs
phantomfs diff     -old before.phfs -new after.phfs
phantomfs watch    -root . -mode inotify
phantomfs perm     -root .
phantomfs entropy  -root . -min 7.0
```

## Performance targets (typical Linux, 4-core, 10k files ~2 GB)
- scan (8 workers):    ~0.25 s
- dupes (xxhash64):    ~0.55 s
- dedup (FastCDC):     ~0.75 s
- bloom build:         ~0.55 s
- xxh64 (1 MiB):       ~13 GB/s single-thread

Numbers depend on storage. Bench your own before trusting them.

## Guarantees
- Every exported function has a doc comment.
- Every algorithm has a test with a real reference vector or property.
- No panics on malformed input in library code — bounds are explicit.
- `-race` clean.

## License
MIT
