# CINT Foundation — Batch A

This update package contains the 12 files extracted from `update4.txt`:
- `go.mod`
- `.gitignore`
- `LICENSE`
- `internal/universe/core/` (types, log, http, ioc, ratelimit)
- `internal/cyber/core/` (types, http, log, ioc)

## Apply to the repository

1. Extract this ZIP into the root of your CINT repository.
2. Review existing files before overwriting them, especially `go.mod`, `.gitignore`, and `LICENSE`.
3. Confirm the repository module path is `github.com/brezzkin-dev/CINT`.
4. Run formatting and tests after all required batches are present:

```sh
gofmt -w internal/universe/core internal/cyber/core
go test ./...
```

This ZIP contains only Batch A/foundation files supplied in `update4.txt`. It is not the complete ~120-file repository tree, and it does not include later batches B–L. Source code was copied from the supplied file without intentional code changes; it has not been compiled or tested here.
