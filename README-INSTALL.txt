# PHANTOMFS v2 — Next Tools Update (UNIVERSE Batch 3/5)

This bundle contains the six Go source files supplied in `update1.txt`:
- DOMAINX
- IDENTRACE
- MAILSCOPE
- PHOTONTRACE
- FORENSIX

It also contains `DISPATCHER-PATCH.txt`, which has the three dispatcher additions for
`cmd/universe/main.go` (imports, switch cases, and handlers).

## Apply

1. Extract this folder into the root of your existing PhantomFS repository.
2. Merge/overwrite the six `.go` files at their matching paths.
3. Open `cmd/universe/main.go` and manually add the three snippets from
   `DISPATCHER-PATCH.txt` to the existing file. Do not replace the whole file.
4. From the repository root, run:

```bash
gofmt -w internal/universe/tools/t27_domainx internal/universe/tools/t28_identrace internal/universe/tools/t29_mailscope internal/universe/tools/t30_photontrace internal/universe/tools/t31_forensix
go test ./...
go build ./cmd/universe
```

The dispatcher snippets reference the module path shown in the supplied update text.
If your repository's `go.mod` uses a different module path, adjust only those import
paths to match the existing module declaration.

## Important

- This is an update bundle, not a complete repository.
- The supplied source text claims all five tools are implemented, but this ZIP has
  not been compiled or tested against your full repository.
- No tool implementation code was intentionally rewritten during packaging.
