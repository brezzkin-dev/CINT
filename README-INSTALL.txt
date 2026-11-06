PHANTOMFS v2 — integration update

This package contains the integration/repository files supplied in update2.txt.
It does not contain the PHANTOMFS, OBSIDIAN, L1GHTXR, or UNIVERSE tool-package
batches listed in the manifest. Those source directories must already exist
in the repository before this integration can build.

Included:
- cmd/universe/main.go — consolidated dispatcher for 35 tools (t01–t20, t22–t36)
- go.mod
- LICENSE
- .gitignore

IMPORTANT:
- The supplied go.mod module path is github.com/ollie/phantomfs.
  Keep it only if that is the intended module path for this repository.
  If your repository uses a different module path, update go.mod and the
  matching github.com/ollie/phantomfs imports consistently.
- This package preserves the supplied source content; it has not been
  compiled or tested against your complete repository.
- Do not overwrite other cmd entrypoints or tool packages with this update.

Apply by extracting this folder and copying its contents into the repository
root, preserving the cmd/universe/main.go path. Then run the verification
commands from your project root:

  gofmt -w cmd/universe/main.go
  go vet ./...
  go build ./cmd/phantomfs ./cmd/universe ./cmd/obsidian ./cmd/l1ghtxr
  go test ./...

Only commit and push after resolving any build/test errors.
