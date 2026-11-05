# L1ghtXr

Ten cyber tools, pure Go, stdlib only. Complements PHANTOMFS.

| # | Tool | Binary subcommand | Feeds / Engine |
|---|---|---|---|
| 1 | Cyber Intelligence Engine | `intel` | ip-api.com, URLhaus, ThreatFox |
| 2 | MALWARESCOPE | `malscope` | debug/pe, debug/elf, string sweep |
| 3 | Digital Forensics Investigation | `dfir` | auth.log, shell history, cron, wtmp |
| 4 | Attack Surface Mapping | `asm` | crt.sh, TCP probe, TLS |
| 5 | Website Security Auditing | `wsa` | headers, TLS, cookies, paths |
| 6 | PACKETCORE | `pcap` | raw PCAP, flow + credential extraction |
| 7 | Cryptographic Analysis | `cryptan` | hash id, dict crack, JWT, AES-GCM, freq |
| 8 | System Security Auditing | `sysaudit` | SUID, /etc/passwd, /etc/shadow, sshd_config, sysctl, /proc/net/tcp |
| 9 | Phishing Detection | `phish` | lexical + punycode + DNS + SPF/DMARC |
| 10 | Vulnerability Intelligence | `vulnintel` | NVD 2.0, EPSS, CISA KEV |

## Build
```bash
go build -o l1ghtxr ./cmd/l1ghtxr
go build -o phantomfs ./cmd/phantomfs
```

## Examples

```bash
l1ghtxr intel     -ioc 1.1.1.1,evil.com,d41d8cd98f00b204e9800998ecf8427e
l1ghtxr malscope  -file sample.exe -out mal.json
l1ghtxr dfir      -root / -out dfir.json
l1ghtxr asm       -domain example.com -out asm.json
l1ghtxr wsa       -url https://example.com -out wsa.json
l1ghtxr pcap      -file capture.pcap -out pcap.json
l1ghtxr cryptan id     -hash 5f4dcc3b5aa765d61d8327deb882cf99
l1ghtxr cryptan crack  -hash 5f4dcc3b5aa765d61d8327deb882cf99 -wordlist rockyou.txt
l1ghtxr cryptan jwt    -token eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoib2xsaWUifQ.sig
l1ghtxr cryptan freq   -in ciphertext.txt
l1ghtxr sysaudit  -root /
l1ghtxr phish     -url https://paypa1.tk/login
l1ghtxr vulnintel cve      -id CVE-2024-3094
l1ghtxr vulnintel packages
```

## Free feeds (no key required)

- ip-api.com — geolocation + ASN (free tier, 45 req/min)
- urlhaus-api.abuse.ch — malware URL feed
- threatfox-api.abuse.ch — IOC feed
- crt.sh — certificate transparency subdomain enum
- NVD 2.0 — CVE data (rate-limited without key)
- api.first.org — EPSS scores
- cisa.gov KEV — known exploited vulnerabilities

## License

MIT
