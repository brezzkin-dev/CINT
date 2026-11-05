package hash

import (
	"io"
	"os"
)

// bufferSize is the streaming read size. 1 MiB keeps allocations minimal
// while still saturating typical disk throughput.
const bufferSize = 1 << 20

// HashFileXXH64 returns the XXH64 hash of the file at path.
// It streams, so memory usage is O(bufferSize), not O(fileSize).
func HashFileXXH64(path string) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	st := NewXXH64(0)
	buf := make([]byte, bufferSize)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			_, _ = st.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
	}
	return st.Sum64(), nil
}

// HashBytesXXH64 hashes an in-memory byte slice.
func HashBytesXXH64(b []byte) uint64 { return XXHash64(b, 0) }
