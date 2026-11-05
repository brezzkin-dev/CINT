package t07_phototrace

import (
	"encoding/binary"
	"fmt"
)

func ParseEXIF(data []byte) map[string]any {
	off := findMarker(data, 0xFFE1)
	if off < 0 {
		return nil
	}
	hdrStart := off + 4
	if hdrStart+6 > len(data) || string(data[hdrStart:hdrStart+6]) != "Exif\x00\x00" {
		return nil
	}
	tiff := data[hdrStart+6:]
	if len(tiff) < 8 {
		return nil
	}
	var le bool
	switch string(tiff[:2]) {
	case "II":
		le = true
	case "MM":
		le = false
	default:
		return nil
	}
	order := binary.ByteOrder(binary.BigEndian)
	if le {
		order = binary.LittleEndian
	}
	ifd0Offset := order.Uint32(tiff[4:8])
	if ifd0Offset+2 > uint32(len(tiff)) {
		return nil
	}
	out := map[string]any{}
	walkIFD(tiff, order, ifd0Offset, out, 0)
	return out
}

func findMarker(data []byte, marker uint16) int {
	hi, lo := byte(marker>>8), byte(marker&0xff)
	for i := 0; i < len(data)-1; i++ {
		if data[i] == hi && data[i+1] == lo {
			return i
		}
	}
	return -1
}

var tagNames = map[uint16]string{
	0x010F: "Make", 0x0110: "Model", 0x0112: "Orientation",
	0x0131: "Software", 0x0132: "DateTime", 0x013B: "Artist",
	0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized",
	0xA002: "PixelXDimension", 0xA003: "PixelYDimension",
}

var typeSizes = map[uint16]int{
	1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1,
}

func walkIFD(tiff []byte, order binary.ByteOrder, off uint32, out map[string]any, depth int) {
	if depth > 3 || off+2 > uint32(len(tiff)) {
		return
	}
	count := order.Uint16(tiff[off : off+2])
	base := off + 2
	for i := uint16(0); i < count; i++ {
		entryOff := base + uint32(i)*12
		if entryOff+12 > uint32(len(tiff)) {
			return
		}
		tag := order.Uint16(tiff[entryOff : entryOff+2])
		typ := order.Uint16(tiff[entryOff+2 : entryOff+4])
		n := order.Uint32(tiff[entryOff+4 : entryOff+8])
		size, ok := typeSizes[typ]
		if !ok {
			continue
		}
		total := int(n) * size
		var valOff uint32
		if total <= 4 {
			valOff = entryOff + 8
		} else {
			valOff = order.Uint32(tiff[entryOff+8 : entryOff+12])
		}
		if valOff+uint32(total) > uint32(len(tiff)) {
			continue
		}
		name := tagNames[tag]
		if name == "" {
			name = fmt.Sprintf("tag_0x%04x", tag)
		}
		switch typ {
		case 2:
			s := tiff[valOff : valOff+uint32(total)]
			end := 0
			for end < len(s) && s[end] != 0 {
				end++
			}
			out[name] = string(s[:end])
		case 3:
			if n >= 1 {
				out[name] = order.Uint16(tiff[valOff : valOff+2])
			}
		case 4:
			if n >= 1 {
				out[name] = order.Uint32(tiff[valOff : valOff+4])
			}
		}
	}
}
