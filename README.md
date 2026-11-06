CINT — Cyber Intelligence Toolkit

"CINT Banner" (assets/cint-banner.png)

<p align="center">
  <strong>RECON · ANALYZE · INVESTIGATE · DEFEND</strong>
</p><p align="center">
  <img src="https://img.shields.io/badge/Language-Go-00ADD8?style=flat-square&logo=go" alt="Go">
  <img src="https://img.shields.io/badge/Go-1.21%2B-blue?style=flat-square" alt="Go 1.21+">
  <img src="https://img.shields.io/badge/Dependencies-Standard%20Library-success?style=flat-square" alt="Dependencies">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" alt="MIT">
  <img src="https://img.shields.io/badge/Platform-Cross--Platform-lightgrey?style=flat-square" alt="Platform">
</p>CINT is a modular command-line toolkit written in Go for filesystem intelligence, OSINT, digital forensics, threat intelligence, network analysis, and security assessment.

The project consists of four executable applications backed by reusable internal packages. Each component has a defined responsibility and provides command-line access to its functionality.

Application| Purpose| Commands / Tools
"phantomfs"| Filesystem intelligence| 16
"universe"| OSINT, forensics, intelligence and network analysis| 40
"obsidian"| Cybersecurity toolkit| 10
"l1ghtxr"| Alternate cyber CLI| 10

Author: L1ghtXr
Module: "github.com/brezzkin-dev/CINT"
Language: Go 1.21+
License: MIT

---

Table of Contents

1. Overview
2. Requirements
3. Installation
4. Build
5. phantomfs
6. universe
7. obsidian
8. l1ghtxr
9. Environment and Data Sources
10. Architecture
11. Testing
12. Security and Limitations
13. License

---

Overview

CINT combines several areas of technical investigation in one Go project.

Design principles

- Native Go implementation.
- Modular package structure.
- Deterministic algorithms and rule-based analysis.
- No AI or machine-learning inference.
- No mandatory API keys.
- JSON output where supported.
- Atomic output writes where implemented.
- Graceful handling of unavailable public data sources.
- Explicit limitations for heuristic and incomplete analysis.

---

Requirements

- Go 1.21 or newer.
- Git.
- Linux, macOS, Windows, or a compatible Go environment.
- Internet access for tools that query public services.

Some operating-system-specific capabilities may not be available on every platform.

---

Installation

Clone the repository:

git clone https://github.com/brezzkin-dev/CINT.git
cd CINT

Build all packages:

go build ./...

Build the applications individually:

go build -o phantomfs ./cmd/phantomfs
go build -o universe ./cmd/universe
go build -o obsidian ./cmd/obsidian
go build -o l1ghtxr ./cmd/l1ghtxr

Run:

./phantomfs help
./universe
./obsidian
./l1ghtxr

Cross-compilation

GOOS=linux GOARCH=amd64 go build -o universe-linux-amd64 ./cmd/universe
GOOS=linux GOARCH=arm64 go build -o universe-linux-arm64 ./cmd/universe
GOOS=darwin GOARCH=arm64 go build -o universe-darwin-arm64 ./cmd/universe
GOOS=windows GOARCH=amd64 go build -o universe-windows-amd64.exe ./cmd/universe

Install with Go

go install github.com/brezzkin-dev/CINT/cmd/universe@latest
go install github.com/brezzkin-dev/CINT/cmd/phantomfs@latest
go install github.com/brezzkin-dev/CINT/cmd/obsidian@latest
go install github.com/brezzkin-dev/CINT/cmd/l1ghtxr@latest

---

Build

Format source code:

gofmt -w $(find . -name '*.go' -type f)

Static analysis:

go vet ./...

Compile:

go build ./...

Run tests:

go test ./...

---

phantomfs

Filesystem intelligence for inspection, analysis, and recovery operations.

phantomfs <command> [flags]

1. scan

Walk a directory tree and collect file information.

phantomfs scan -root /path [-max-depth N] [-min-size B] [-workers N] [-json]

Flags:

- "-root" — scan root, default ".".
- "-max-depth" — maximum traversal depth; "0" means unlimited.
- "-min-size" — minimum file size in bytes.
- "-workers" — worker count; "0" uses available CPUs.
- "-json" — emit JSON output.

2. hidden

Detect hidden and unusual filesystem entries.

phantomfs hidden -root /path [-json]

Checks include dotfiles, symlinks, unreadable entries, deep paths, zero-byte files, executable files, hardlinks, and sparse files.

3. dupes

Find duplicate files using parallel xxhash64 hashing.

phantomfs dupes -root /path [-json]

Groups files by size, hashes candidates, and reports groups with matching hashes and estimated reclaimable space.

4. watch

Monitor filesystem changes.

phantomfs watch -root /path [-mode auto|poll|inotify] [-poll 2s] [-json]

- "auto" — attempts inotify on Linux and falls back to polling.
- "poll" — polling mode.
- "inotify" — Linux-specific event monitoring.

5. tree

Render a directory tree.

phantomfs tree -root /path

6. classify

Classify files using rules and magic-byte detection.

phantomfs classify -root /path [-json]

Categories include temporary files, archives, executables, scripts, configuration files, keys, empty files, and large files.

7. recover

Reconstruct missing parent directories encountered during a filesystem walk.

phantomfs recover -root /path

This operation reconstructs directories only. It does not recover deleted file contents.

8. snapshot

Create a binary filesystem snapshot.

phantomfs snapshot -root /path [-out snapshot.phfs]

9. diff

Compare two filesystem snapshots.

phantomfs diff -old old.phfs -new new.phfs [-json]

Reports added, modified, and deleted entries.

10. carve

Extract supported embedded file formats from a raw input.

phantomfs carve -file disk.img [-out carved/] [-json]

Supported signatures include JPEG, PNG, GIF, PDF, and ZIP.

11. perm

Audit filesystem permissions.

phantomfs perm -root /path [-json]

Checks setuid, setgid, sticky bits, world-writable files, hardlinks, and sparse files.

12. entropy

Perform block-level Shannon entropy analysis.

phantomfs entropy -root /path [-block 4096] [-min 7.0] [-json]

Reports files whose maximum block entropy exceeds the configured threshold. High entropy can indicate compressed, packed, or encrypted content; it is not proof of malicious activity.

13. dedup

Analyze content-defined chunks using FastCDC.

phantomfs dedup -root /path [-min 512] [-avg 4096] [-max 65536] [-json]

Reports total chunks, unique chunks, duplicate chunks, and estimated reclaimable bytes.

14. bloom

Build a Bloom filter from file hashes and test membership.

phantomfs bloom -root /path [-check-file path] [-check-hash hex] [-fp 0.001] [-json]

15. hash

Calculate xxhash64 for one file.

phantomfs hash -file path [-json]

16. magic

Identify files through magic-byte signatures.

phantomfs magic -file path [-json]

The signature table covers images, archives, executables, fonts, audio, video, documents, WebAssembly, and PEM formats.

Interactive mode

phantomfs

Starts the interactive command interface.

---

universe

A collection of OSINT, forensic, intelligence, and network analysis tools.

universe <tool> [flags]

Batch 0 — Reconnaissance and OSINT

osintcore — IOC router

Routes a target based on its indicator type.

universe osintcore -target <value>

Routing:

- IP → "ipintel"
- Domain or URL → "domaintrace" and "ipintel"
- Email → "mailtrace"
- Username → "userfinder"

geoint — Geolocation

universe geoint -ip <IP>
universe geoint -coords <lat,lng>
universe geoint -image photo.jpg

IP geolocation, reverse geocoding, and EXIF GPS extraction.

domaintrace — Domain intelligence

universe domaintrace -domain example.com

DNS records, RDAP registration data, and Certificate Transparency history.

ipintel — IP intelligence

universe ipintel -ip 1.1.1.1

Geo, ASN, proxy/VPN indicators, RDAP network information, and reverse DNS.

userfinder — Username presence

universe userfinder -user <name>

Checks username presence across supported platforms. Results distinguish confirmed, possible, not found, blocked, and unknown statuses.

mailtrace — Email intelligence

universe mailtrace -email user@example.com

MX, SPF, DMARC, Gravatar hash, and supported password-range checks using k-anonymity.

phototrace — Image forensics

universe phototrace -file image.jpg [-deep]

EXIF, JPEG quantization tables, error-level analysis, noise variance, and chromatic aberration indicators.

Deep mode adds double-JPEG, copy-move, and JPEG ghost analysis.

Results are heuristic indicators, not forensic proof.

socialmap — Handle clustering

universe socialmap -user <name>

Summarizes confirmed username presence across supported platforms.

linktrace — Redirect analysis

universe linktrace -url https://example.com

Follows supported redirect chains with URL and destination validation. Private and loopback destinations are blocked.

metatrack — File metadata

universe metatrack -file <path>

Collects supported file hashes and metadata from image, PDF, MP3, and Office formats.

breachwatch — Breach intelligence

universe breachwatch -email user@example.com
universe breachwatch -domain example.com

Uses supported public breach and password-range services. Availability depends on the source and its access policy.

darkintel — Threat feeds

universe darkintel -ioc <value>
universe darkintel -feed urlhaus
universe darkintel -feed threatfox
universe darkintel -feed feodo

Queries supported threat intelligence feeds.

certtrace — TLS and certificate history

universe certtrace -domain example.com

Inspects TLS certificates and Certificate Transparency history.

geoarchive — Geospatial archive

universe geoarchive -coords <lat,lng>
universe geoarchive -place <name>

Reverse geocoding, nearby map features, and supported geographic references.

entitylink — Entity graph

universe entitylink -target <value>

Correlates supported entity types, including email, domain, IP, and username.

Batch 1 — Forensics

memoryx — Memory dump IOC extraction

universe memoryx -file memory.dump [-min 6]

Extracts supported indicators from memory dumps, including URLs, IP addresses, email addresses, hashes, keywords, embedded PE headers, and high-entropy regions.

binarycore — PE and ELF analysis

universe binarycore -file sample.exe

Inspects executable sections, entropy, entry points, imports, overlays, URLs, and file signatures.

evidencevault — Evidence management

universe evidencevault init -vault ./case01
universe evidencevault add -vault ./case01 -file evidence.bin -label "disk image"
universe evidencevault verify -vault ./case01
universe evidencevault list -vault ./case01

Uses content-addressed storage, SHA-256 hashes, and a manifest chain.

Limitation: the local hash chain is verifiable, but it is not externally anchored. A privileged attacker able to rewrite both the manifest and stored blobs may be able to reconstruct a consistent vault.

timelinex — Timeline correlation

universe timelinex -in file1.json,file2.jsonl,/var/log/auth.log

Supports configured timestamp extraction from JSON, JSONL, syslog, wtmp, and filesystem metadata.

Optional time filters:

universe timelinex -in events.json [-from RFC3339] [-to RFC3339]

intelgraph — Intelligence graph

universe intelgraph -in report1.json,report2.json -format dot -out graph.dot

Extracts supported entities from JSON reports and generates DOT, JSON, or text output.

Batch 2 — Intelligence

shadowtrace — Public trace correlation

universe shadowtrace -target <domain|email|user>

Correlates supported public sources and reports matching indicators.

ghostint — Multi-feed threat intelligence

universe ghostint -ioc <ip,domain,hash> [-feed all]

Queries supported threat feeds and combines available findings into a risk-oriented report.

entityx — Entity co-occurrence

universe entityx -in file1.txt,file2.json [-min 2]

Extracts supported entities and analyzes co-occurrence relationships.

geocrypt — Geospatial calculations

universe geocrypt -coords <lat,lng>
universe geocrypt -coords <lat,lng> -from <point> -to <point>
universe geocrypt -coords <lat,lng> -when <RFC3339>
universe geocrypt -coords <lat,lng> -image photo.jpg

Includes Haversine distance, bearing, midpoint, sun position, UTM information, and supported geographic lookups.

ipnexus — Extended IP intelligence

universe ipnexus -ip 8.8.8.8

Combines geolocation, ASN, RDAP, reverse DNS, Tor exit checks, and TLS inspection.

Batch 3 — Domain, media, and identity

domainx — DNS enumeration

universe domainx -domain example.com

Queries supported DNS record types, including A, AAAA, MX, NS, TXT, SPF, DMARC, CNAME, SOA, CAA, DNSKEY, and DS.

identrace — Profile APIs

universe identrace -user <name> [-email user@example.com]

Queries supported public profile APIs, including GitHub, Reddit, Hacker News, Keybase, and Mastodon.

mailscope — Email analysis

universe mailscope -file message.eml

Analyzes supported email headers, Received chains, DKIM body hashes, SPF, DMARC, and sender consistency indicators.

Limitation: this tool does not perform complete DKIM RSA signature verification. Body-hash analysis is not equivalent to full signature validation.

photontrace — Image comparison

universe photontrace -url https://example.com/image.jpg
universe photontrace -file image.jpg -compare other.jpg

Uses supported image analysis and perceptual hashes. Remote retrieval applies destination validation.

forensix — Local system triage

universe forensix [-root ~] [-recent-days 7]

Inspects supported shell history, browser artifacts, autostart locations, recent files, and selected system logs.

Batch 4 — Security analysis

malshield — Malware static analysis

universe malshield -file sample.exe

Analyzes PE/ELF metadata, section entropy, imports, overlays, and built-in YARA-lite rules.

Scores and rule matches are indicators for further investigation, not a malware verdict.

packetx — PCAP analysis

universe packetx -file capture.pcap

Analyzes supported packet captures for IP traffic, flows, DNS, HTTP, TLS SNI, selected credentials, beacon indicators, and port-scan patterns.

Limitation: no full TCP stream reassembly. Some out-of-order or fragmented application data may not be reconstructed correctly.

vulnintel — CVE intelligence

universe vulnintel cve -id CVE-2024-3094
universe vulnintel batch -file cves.txt
universe vulnintel banner -banner "Apache/2.4.49"

Uses supported vulnerability information sources, including NVD, EPSS, and CISA KEV.

certnexus — Certificate intelligence

universe certnexus -domain example.com

Inspects TLS certificate chains, Certificate Transparency history, issuers, wildcard certificates, and expiration information.

l1xcore — IOC orchestrator

universe l1xcore -target <value>

Dispatches targets to supported tools and combines findings.

Batch 5 — Network tools

webcrawl — Web crawler

universe webcrawl -seed https://example.com [-depth 3] [-pages 100] [-same-host]

Uses a breadth-first crawling approach to collect links, forms, script references, selected endpoint strings, and HTML comments.

Limitation: JavaScript is not executed. Client-rendered routes may not be discovered.

subdomx — Passive subdomain enumeration

universe subdomx -domain example.com [-resolve]

Collects subdomain information from supported passive sources and deduplicates results.

hashcrack — Dictionary hash testing

universe hashcrack -hash <hex> -wordlist <path> [-rules]

Supports MD5, SHA-1, SHA-256, and SHA-512 dictionary testing.

Limitation: this is not a universal password recovery tool. It does not support every password-hashing algorithm or attack strategy.

portx — TCP port scanner

universe portx -target <ip|cidr|host> [-ports top|full|1-1024|22,80] [-workers 500] [-timeout 2s]

Performs TCP connection checks and supported service/banner inspection.

Limitation: TCP connect scanning only; no SYN scan.

wifi — 802.11 PCAP analysis

universe wifi -file capture.pcap

Analyzes supported 802.11 captures for beacon frames, probe requests, deauthentication events, and EAPOL handshake indicators.

Limitation: does not configure monitor mode, perform channel hopping, or recover wireless credentials.

---

obsidian

A CLI exposing the cyber modules.

obsidian <tool> [flags]

intel — Threat intelligence

obsidian intel [-file iocs.txt]
obsidian intel -ioc <ip,domain,hash> [-out report.json]

Queries supported threat intelligence sources.

malscope — Malware analysis

obsidian malscope -file sample.bin [-yara custom.yara] [-out report.json]

PE/ELF inspection, import analysis, entropy, and supported YARA-lite rules.

dfir — Digital forensics

obsidian dfir [-root /] [-out report.json]

Inspects supported system artifacts, shell history, logs, cron entries, and IOC indicators.

asm — Attack surface mapping

obsidian asm -domain example.com [-full-ports] [-out report.json]

Performs domain-related discovery and supported port inspection.

wsa — Web security audit

obsidian wsa -url https://target.example [-inject] [-takeover] [-out report.json]

Includes security-header checks, WAF fingerprinting, cookie checks, and TLS inspection.

The "-inject" option enables active probes. Only use it on systems you own or are explicitly authorized to test.

pcap — Packet capture analysis

obsidian pcap -file capture.pcap [-out report.json]

Analyzes supported network packet captures, flows, DNS, HTTP, TLS SNI, and selected credential indicators.

cryptan — Cryptographic analysis

obsidian cryptan id -hash <hex>
obsidian cryptan crack -hash <hex> -wordlist wordlist.txt
obsidian cryptan jwt -token <jwt>
obsidian cryptan encrypt -key <hex> -in plain.bin -out cipher.bin
obsidian cryptan decrypt -key <hex> -in cipher.bin -out plain.bin
obsidian cryptan freq -in text.txt
obsidian cryptan xor -in ciphertext.bin
obsidian cryptan vig -in ciphertext.txt
obsidian cryptan rsa -n <modulus> [-e 65537]
obsidian cryptan ecb -in ciphertext.bin

Features include hash identification, dictionary testing, JWT inspection, AES-GCM operations, frequency analysis, XOR analysis, Vigenère analysis, weak RSA analysis, and ECB pattern detection.

sysaudit — System audit

obsidian sysaudit [-root /] [-out report.json]

Inspects supported system configuration, permissions, Linux capabilities, sudoers, cron, and container indicators.

phish — Phishing analysis

obsidian phish -url https://suspicious.example [-out report.json]

Uses URL characteristics, domain indicators, and supported SPF/DMARC checks.

vulnintel — Vulnerability intelligence

obsidian vulnintel cve -id CVE-2024-3094
obsidian vulnintel packages

Queries supported vulnerability sources and package information providers.

---

l1ghtxr

An alternate executable exposing the same cyber modules as "obsidian".

l1ghtxr <tool> [flags]

Available tools:

l1ghtxr intel
l1ghtxr malscope
l1ghtxr dfir
l1ghtxr asm
l1ghtxr wsa
l1ghtxr pcap
l1ghtxr cryptan
l1ghtxr sysaudit
l1ghtxr phish
l1ghtxr vulnintel

Both executables use the shared "internal/cyber" packages.

---

Environment and Data Sources

CINT does not require a mandatory ".env" file or global configuration file.

Some tools query public services. Examples include:

Service| Usage
IP-API| IP geolocation
OpenStreetMap Nominatim| Reverse geocoding
Overpass API| Geographic feature lookup
RDAP| Domain and network registration
crt.sh| Certificate Transparency
URLhaus| Threat intelligence
ThreatFox| Threat intelligence
Feodo Tracker| C2 indicators
OpenPhish| Phishing intelligence
Have I Been Pwned| Supported breach information
Pwned Passwords| K-anonymity password-range checks
NVD| Vulnerability information
FIRST EPSS| Exploit prediction scoring
CISA KEV| Known exploited vulnerabilities
GitHub API| Public profile and code intelligence
Hacker News API| Public profile information
Mastodon API| Public profile information
Wayback Machine| Archived URL availability
AlienVault OTX| Threat intelligence

Availability and rate limits are controlled by the external providers and may change.

Respect each provider's terms of service, rate limits, and acceptable-use policies.

---

Architecture

CINT/
├── go.mod
├── LICENSE
├── README.md
├── cmd/
│   ├── phantomfs/
│   ├── universe/
│   ├── obsidian/
│   └── l1ghtxr/
│
├── internal/
│   ├── core/
│   ├── hash/
│   ├── chunk/
│   ├── magic/
│   ├── entropy/
│   ├── permaudit/
│   ├── carve/
│   ├── bloom/
│   ├── index/
│   ├── watch/
│   ├── scan/
│   ├── modules/
│   │   ├── dup/
│   │   ├── classify/
│   │   ├── hidden/
│   │   ├── tree/
│   │   └── recover/
│   │
│   ├── cyber/
│   │   ├── core/
│   │   ├── asm/
│   │   ├── cryptan/
│   │   ├── dfir/
│   │   ├── intel/
│   │   ├── malscope/
│   │   ├── pcap/
│   │   ├── phish/
│   │   ├── sysaudit/
│   │   ├── vulnintel/
│   │   └── wsa/
│   │
│   └── universe/
│       ├── core/
│       └── tools/
│
└── tests/
    └── integration_test.go

---

Testing

Run the complete test suite:

go test ./...

Run static analysis:

go vet ./...

Build every package:

go build ./...

Check formatting:

gofmt -w $(find . -name '*.go' -type f)

Optional race detection:

go test -race ./...

---

Security and Limitations

CINT is a technical toolkit. Its output must be interpreted in context.

- Heuristic detections can produce false positives and false negatives.
- Public API availability is not guaranteed.
- Geolocation results are estimates.
- Packet analysis is limited by capture quality and supported protocols.
- Static malware analysis cannot establish that a file is safe.
- Hash matching does not prove file identity beyond the selected algorithm's properties.
- Certificate and DNS data can change after collection.
- Active web probes can affect target systems.

Only perform active security testing against systems you own or have explicit authorization to assess.

Do not use this project to access, disrupt, or interfere with systems without permission.

---

License

CINT is released under the MIT License.

See "LICENSE" (LICENSE) for the full license text.

---

Author

L1ghtXr

Repository: https://github.com/brezzkin-dev/CINT

Issues and contributions are welcome through GitHub.

<p align="center">
  <strong>CINT — Cyber Intelligence Toolkit</strong><br>
  <sub>Built for research. Designed for security.</sub>
</p>
