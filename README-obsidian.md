# OBSIDIAN

**Author: L1ghtXr**

Ten cyber tools, pure Go, stdlib only. Complements PHANTOMFS.

| # | Tool | Subcommand | Engine |
|---|---|---|---|
| 1 | Cyber Intelligence | `intel` | ip-api, URLhaus, ThreatFox |
| 2 | MALWARESCOPE | `malscope` | PE/ELF, imphash, overlay, YARA-lite |
| 3 | Digital Forensics | `dfir` | auth.log, wtmp, history, cron |
| 4 | Attack Surface | `asm` | crt.sh, port scan, TLS |
| 5 | Website Security | `wsa` | headers, TLS, cookies, paths |
| 6 | PACKETCORE | `pcap` | flow + credential extraction |
| 7 | Crypto Analysis | `cryptan` | hash, JWT, AES, XOR, Vigenère, RSA, ECB |
| 8 | System Audit | `sysaudit` | SUID, shadow, SSH, sysctl, ports |
| 9 | Phishing Detect | `phish` | lexical, typosquat, redirect, SPF/DMARC |
| 10 | Vuln Intel | `vulnintel` | NVD, EPSS, CISA KEV, batch |

## Build
```bash
go build -o obsidian ./cmd/obsidian
go build -o phantomfs ./cmd/phantomfs
```

## License
MIT
