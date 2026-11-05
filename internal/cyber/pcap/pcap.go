// Package pcap — PACKETCORE. Flow analysis + credential sniffing from PCAP.
package pcap

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/ollie/phantomfs/internal/cyber/core"
)

type cred struct {
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	Proto string `json:"proto"`
	Kind  string `json:"kind"`
	User  string `json:"user,omitempty"`
	Pass  string `json:"pass,omitempty"`
}

type flow struct {
	Key   string
	Pkts  int
	Bytes int
}

func readPCAP(data []byte) ([][]byte, bool, error) {
	if len(data) < 24 {
		return nil, false, fmt.Errorf("short pcap")
	}
	magic := binary.LittleEndian.Uint32(data[0:4])
	var le, ns bool
	switch magic {
	case 0xa1b2c3d4:
		le = true
	case 0xd4c3b2a1:
		le = false
	case 0xa1b23c4d:
		le = true
		ns = true
	case 0x4d3cb2a1:
		le = false
		ns = true
	default:
		return nil, false, fmt.Errorf("bad magic")
	}
	_ = ns
	off := 24
	var pkts [][]byte
	for off+16 <= len(data) {
		var incl int
		if le {
			incl = int(binary.LittleEndian.Uint32(data[off+8 : off+12]))
		} else {
			incl = int(binary.BigEndian.Uint32(data[off+8 : off+12]))
		}
		off += 16
		if off+incl > len(data) {
			break
		}
		pkts = append(pkts, data[off:off+incl])
		off += incl
	}
	return pkts, le, nil
}

func parseFrame(pkt []byte) (proto uint8, srcIP, dstIP string, sport, dport uint16, payload []byte) {
	if len(pkt) < 14 {
		return
	}
	et := binary.BigEndian.Uint16(pkt[12:14])
	if et != 0x0800 || len(pkt) < 34 {
		return
	}
	ip := pkt[14:]
	ihl := int(ip[0]&0x0f) * 4
	if len(ip) < ihl {
		return
	}
	proto = ip[9]
	srcIP = net.IP(ip[12:16]).String()
	dstIP = net.IP(ip[16:20]).String()
	l4 := ip[ihl:]
	switch proto {
	case 6:
		if len(l4) < 20 {
			return
		}
		sport = binary.BigEndian.Uint16(l4[0:2])
		dport = binary.BigEndian.Uint16(l4[2:4])
		doff := int((l4[12] >> 4) & 0x0f) * 4
		if len(l4) >= doff {
			payload = l4[doff:]
		}
	case 17:
		if len(l4) < 8 {
			return
		}
		sport = binary.BigEndian.Uint16(l4[0:2])
		dport = binary.BigEndian.Uint16(l4[2:4])
		plen := int(binary.BigEndian.Uint16(l4[4:6]))
		if plen >= 8 && len(l4) >= plen {
			payload = l4[8:plen]
		}
	}
	return
}

func extractCreds(proto uint8, src, dst string, sport, dport uint16, payload []byte) []cred {
	var out []cred
	if len(payload) == 0 {
		return out
	}
	up := strings.ToUpper(string(payload))
	if dport == 21 || sport == 21 {
		if strings.HasPrefix(up, "USER ") {
			u := strings.TrimSpace(string(payload[5:]))
			out = append(out, cred{Src: src, Dst: dst, Proto: "ftp", Kind: "user", User: u})
		} else if strings.HasPrefix(up, "PASS ") {
			p := strings.TrimSpace(string(payload[5:]))
			out = append(out, cred{Src: src, Dst: dst, Proto: "ftp", Kind: "pass", Pass: p})
		}
	}
	if dport == 80 || sport == 80 || dport == 8080 || sport == 8080 {
		if strings.HasPrefix(up, "GET ") || strings.HasPrefix(up, "POST ") {
			head := string(payload)
			if i := strings.Index(head, "\r\n"); i > 0 {
				head = head[:i]
			}
			if strings.Contains(strings.ToLower(head), "authorization: basic ") {
				idx := strings.Index(strings.ToLower(head), "authorization: basic ")
				if idx >= 0 {
					token := strings.TrimSpace(head[idx+len("authorization: basic "):])
					out = append(out, cred{Src: src, Dst: dst, Proto: "http", Kind: "basic", User: token})
				}
			}
		}
	}
	return out
}

func Analyze(path string) (*core.Result, error) {
	data, err := osReadFile(path)
	if err != nil {
		return nil, err
	}
	r := core.NewResult("pcap", path)

	pkts, _, err := readPCAP(data)
	if err != nil {
		r.Add(core.Finding{Tool: "pcap", Severity: core.SevHigh, Title: "parse error", Detail: err.Error()})
		r.Finish()
		return r, nil
	}

	flows := map[string]*flow{}
	var creds []cred
	dnsNames := map[string]int{}
	for _, pkt := range pkts {
		proto, src, dst, sport, dport, payload := parseFrame(pkt)
		if src == "" {
			continue
		}
		key := fmt.Sprintf("%s:%d-%s:%d/%d", src, sport, dst, dport, proto)
		f, ok := flows[key]
		if !ok {
			f = &flow{Key: key}
			flows[key] = f
		}
		f.Pkts++
		f.Bytes += len(payload)

		if proto == 17 && dport == 53 && len(payload) > 12 {
			if name := parseDNSQuestion(payload); name != "" {
				dnsNames[name]++
			}
		}
		creds = append(creds, extractCreds(proto, src, dst, sport, dport, payload)...)
	}

	if len(creds) > 0 {
		r.Add(core.Finding{
			Tool: "pcap", Severity: core.SevCrit,
			Title: fmt.Sprintf("%d credentials in cleartext", len(creds)),
			Detail: "passwords transmitted without encryption",
			Evidence: map[string]any{"creds": creds},
		})
	}
	r.AddExtra("packet_count", len(pkts))
	r.AddExtra("flow_count", len(flows))
	r.AddExtra("creds", creds)
	r.AddExtra("dns_top", topN(dnsNames, 20))
	r.Finish()
	return r, nil
}

func parseDNSQuestion(d []byte) string {
	qd := binary.BigEndian.Uint16(d[4:6])
	if qd < 1 {
		return ""
	}
	off := 12
	var labels []string
	for off < len(d) {
		l := int(d[off])
		off++
		if l == 0 {
			break
		}
		if off+l > len(d) {
			break
		}
		labels = append(labels, string(d[off:off+l]))
		off += l
	}
	return strings.Join(labels, ".")
}

func topN(m map[string]int, n int) []map[string]any {
	type kv struct {
		k string
		v int
	}
	var arr []kv
	for k, v := range m {
		arr = append(arr, kv{k, v})
	}
	for i := 0; i < len(arr); i++ {
		for j := i + 1; j < len(arr); j++ {
			if arr[j].v > arr[i].v {
				arr[i], arr[j] = arr[j], arr[i]
			}
		}
	}
	if len(arr) > n {
		arr = arr[:n]
	}
	out := make([]map[string]any, len(arr))
	for i, e := range arr {
		out[i] = map[string]any{"name": e.k, "count": e.v}
	}
	return out
}
