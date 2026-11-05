package t07_phototrace

import (
	"hash/fnv"
	"image"
	"sort"
)

type Region struct {
	X1, Y1 int     `json:"x1"`
	X2, Y2 int     `json:"x2"`
	Score  float64 `json:"score"`
	Hash   string  `json:"hash"`
}

type CopyMoveResult struct {
	BlockSize  int      `json:"block_size"`
	Duplicates int      `json:"duplicates"`
	Regions    []Region `json:"regions"`
}

func DetectCopyMove(img image.Image) *CopyMoveResult {
	b := img.Bounds()
	const bs = 16
	const minShift = 32
	type block struct {
		x, y int
		hash uint64
	}
	var blocks []block
	for y := b.Min.Y; y+bs <= b.Max.Y; y += bs {
		for x := b.Min.X; x+bs <= b.Max.X; x += bs {
			h := fnv.New64a()
			for yy := 0; yy < bs; yy += 2 {
				for xx := 0; xx < bs; xx += 2 {
					r, g, bb, _ := img.At(x+xx, y+yy).RGBA()
					h.Write([]byte{byte(r >> 8), byte(g >> 8), byte(bb >> 8)})
				}
			}
			blocks = append(blocks, block{x: x, y: y, hash: h.Sum64()})
		}
	}
	byHash := map[uint64][]block{}
	for _, b2 := range blocks {
		byHash[b2.hash] = append(byHash[b2.hash], b2)
	}
	var regions []Region
	for h, list := range byHash {
		if len(list) < 2 {
			continue
		}
		for i := 0; i < len(list); i++ {
			for j := i + 1; j < len(list); j++ {
				dx := list[i].x - list[j].x
				dy := list[i].y - list[j].y
				if dx < 0 {
					dx = -dx
				}
				if dy < 0 {
					dy = -dy
				}
				if dx+dy < minShift {
					continue
				}
				regions = append(regions, Region{
					X1: list[i].x, Y1: list[i].y,
					X2: list[j].x, Y2: list[j].y,
					Score: 1.0, Hash: hashHex(h),
				})
			}
		}
	}
	sort.Slice(regions, func(i, j int) bool { return regions[i].Score > regions[j].Score })
	if len(regions) > 40 {
		regions = regions[:40]
	}
	return &CopyMoveResult{BlockSize: bs, Duplicates: len(regions), Regions: regions}
}

func hashHex(v uint64) string {
	const hex = "0123456789abcdef"
	var b [16]byte
	for i := 15; i >= 0; i-- {
		b[i] = hex[v&0xf]
		v >>= 4
	}
	return string(b[:])
}
