package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/ollie/phantomfs/internal/cyber/asm"
	"github.com/ollie/phantomfs/internal/cyber/core"
	"github.com/ollie/phantomfs/internal/cyber/cryptan"
	"github.com/ollie/phantomfs/internal/cyber/dfir"
	"github.com/ollie/phantomfs/internal/cyber/intel"
	"github.com/ollie/phantomfs/internal/cyber/malscope"
	"github.com/ollie/phantomfs/internal/cyber/pcap"
	"github.com/ollie/phantomfs/internal/cyber/phish"
	"github.com/ollie/phantomfs/internal/cyber/sysaudit"
	"github.com/ollie/phantomfs/internal/cyber/vulnintel"
	"github.com/ollie/phantomfs/internal/cyber/wsa"
)

const version = "1.0.1"

const banner = `
   __    _  __     __  __     __  __
  / /   (_)/ /_   / / / /_   / / / /___
 / /   / // __ \ / /_/ / /  / /_/ / __ \
/ /___/ // / / // __  / /__/ __  / /_/ /
\____/_//_/ /_//_/ /_/\___/_/ /_/\____/
  L1ghtXr ` + version + ` · 10 cyber tools · ` + runtime.Version() + `
`

func main() {
	if len(os.Args) < 2 {
		interactive()
		return
	}
	dispatch(os.Args[1], os.Args[2:])
}

func dispatch(cmd string, args []string) {
	switch cmd {
	case "intel":
		cmdIntel(args)
	case "malscope":
		cmdMalscope(args)
	case "dfir":
		cmdDFIR(args)
	case "asm":
		cmdASM(args)
	case "wsa":
		cmdWSA(args)
	case "pcap":
		cmdPCAP(args)
	case "cryptan":
		cmdCryptan(args)
	case "sysaudit":
		cmdSysaudit(args)
	case "phish":
		cmdPhish(args)
	case "vulnintel":
		cmdVulnIntel(args)
	case "version", "-v", "--version":
		fmt.Printf("l1ghtxr v%s\n", version)
	case "help", "-h", "--help":
		help()
	case "exit", "quit":
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown: %s\n", cmd)
		help()
		os.Exit(2)
	}
}

func help() {
	fmt.Print(banner)
	fmt.Print(`
tools:
  intel        [-file iocs.txt | -ioc ip,domain,hash] [-out report.json]
  malscope     -file sample.bin [-yara custom.yara] [-out report.json]
  dfir         [-root /] [-out report.json]
  asm          -domain example.com [-full-ports] [-out report.json]
  wsa          -url https://target [-inject] [-takeover] [-out report.json]
  pcap         -file capture.pcap [-out report.json]
  cryptan      {id|crack|jwt|encrypt|decrypt|freq} [flags]
  sysaudit     [-root /] [-out report.json]
  phish        -url https://suspicious.tld/path [-out report.json]
  vulnintel    {cve|packages} [flags]
  version, help
`)
}

func interactive() {
	fmt.Println(banner)
	sc := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("l1ghtxr> ")
		if !sc.Scan() {
			return
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		dispatch(parts[0], parts[1:])
	}
}

func emit(r *core.Result, out string) {
	r.Finish()
	if out != "" {
		if err := r.SaveJSON(out); err != nil {
			fmt.Fprintf(os.Stderr, "save failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "saved: %s\n", out)
	}
	b, err := json.MarshalIndent(map[string]any{
		"tool": r.Tool, "target": r.Target,
		"summary": r.Summary(), "findings": r.Findings, "extra": r.Extra,
	}, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal failed: %v\n", err)
		os.Exit(1)
	}
	os.Stdout.Write(b)
	os.Stdout.Write([]byte("\n"))
}

func cmdIntel(args []string) {
	fs := flag.NewFlagSet("intel", flag.ExitOnError)
	file := fs.String("file", "", "file with one IOC per line")
	ioc := fs.String("ioc", "", "comma-separated IOCs")
	out := fs.String("out", "", "output JSON report")
	_ = fs.Parse(args)

	var iocs []string
	if *file != "" {
		b, err := os.ReadFile(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				iocs = append(iocs, l)
			}
		}
	}
	if *ioc != "" {
		for _, s := range strings.Split(*ioc, ",") {
			if s = strings.TrimSpace(s); s != "" {
				iocs = append(iocs, s)
			}
		}
	}
	if len(iocs) == 0 {
		fmt.Fprintln(os.Stderr, "intel: -file or -ioc required")
		os.Exit(2)
	}
	emit(intel.Enrich(context.Background(), iocs), *out)
}

func cmdMalscope(args []string) {
	fs := flag.NewFlagSet("malscope", flag.ExitOnError)
	file := fs.String("file", "", "binary to analyze")
	yaraPath := fs.String("yara", "", "custom YARA-lite rules file")
	out := fs.String("out", "", "output JSON report")
	_ = fs.Parse(args)
	if *file == "" {
		fmt.Fprintln(os.Stderr, "malscope: -file required")
		os.Exit(2)
	}
	r, err := malscope.Analyze(*file, *yaraPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdDFIR(args []string) {
	fs := flag.NewFlagSet("dfir", flag.ExitOnError)
	root := fs.String("root", "/", "root path")
	out := fs.String("out", "", "output JSON report")
	_ = fs.Parse(args)
	r, err := dfir.Investigate(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdASM(args []string) {
	fs := flag.NewFlagSet("asm", flag.ExitOnError)
	domain := fs.String("domain", "", "apex domain")
	full := fs.Bool("full-ports", false, "scan 1-65535 (slow)")
	out := fs.String("out", "", "output JSON report")
	_ = fs.Parse(args)
	if *domain == "" {
		fmt.Fprintln(os.Stderr, "asm: -domain required")
		os.Exit(2)
	}
	emit(asm.Map(context.Background(), *domain, *full), *out)
}

func cmdWSA(args []string) {
	fs := flag.NewFlagSet("wsa", flag.ExitOnError)
	target := fs.String("url", "", "target URL")
	inject := fs.Bool("inject", false, "run injection probes")
	takeover := fs.Bool("takeover", false, "subdomain takeover check")
	out := fs.String("out", "", "output JSON report")
	_ = fs.Parse(args)
	if *target == "" {
		fmt.Fprintln(os.Stderr, "wsa: -url required")
		os.Exit(2)
	}
	emit(wsa.Audit(context.Background(), *target, wsa.Options{Inject: *inject, Takeover: *takeover}), *out)
}

func cmdPCAP(args []string) {
	fs := flag.NewFlagSet("pcap", flag.ExitOnError)
	file := fs.String("file", "", "pcap file")
	out := fs.String("out", "", "output JSON report")
	_ = fs.Parse(args)
	if *file == "" {
		fmt.Fprintln(os.Stderr, "pcap: -file required")
		os.Exit(2)
	}
	r, err := pcap.Analyze(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdCryptan(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "cryptan: {id|crack|jwt|encrypt|decrypt|freq}")
		os.Exit(2)
	}
	sub := args[0]
	fs := flag.NewFlagSet("cryptan-"+sub, flag.ExitOnError)
	switch sub {
	case "id":
		h := fs.String("hash", "", "hash to identify")
		out := fs.String("out", "", "output")
		_ = fs.Parse(args[1:])
		if *h == "" {
			fmt.Fprintln(os.Stderr, "cryptan id: -hash required")
			os.Exit(2)
		}
		algo, speed := cryptan.IdentifyHash(*h)
		r := core.NewResult("cryptan-id", *h)
		r.AddExtra("algo", algo)
		r.AddExtra("speed", speed)
		emit(r, *out)
	case "crack":
		h := fs.String("hash", "", "target hash")
		wl := fs.String("wordlist", "/usr/share/wordlists/rockyou.txt", "wordlist")
		out := fs.String("out", "", "output")
		_ = fs.Parse(args[1:])
		if *h == "" {
			fmt.Fprintln(os.Stderr, "cryptan crack: -hash required")
			os.Exit(2)
		}
		emit(cryptan.Crack(*h, *wl), *out)
	case "jwt":
		tok := fs.String("token", "", "JWT")
		out := fs.String("out", "", "output")
		_ = fs.Parse(args[1:])
		emit(cryptan.DecodeJWT(*tok), *out)
	case "encrypt", "decrypt":
		key := fs.String("key", "", "hex AES key (16/24/32 bytes)")
		in := fs.String("in", "", "input file")
		outFile := fs.String("out", "", "output file")
		_ = fs.Parse(args[1:])
		if *key == "" || *in == "" || *outFile == "" {
			fmt.Fprintln(os.Stderr, "cryptan: -key, -in, -out required")
			os.Exit(2)
		}
		if err := cryptan.AESCrypt(sub == "encrypt", *key, *in, *outFile); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("%s OK: %s -> %s\n", sub, *in, *outFile)
	case "freq":
		in := fs.String("in", "", "input text or file")
		_ = fs.Parse(args[1:])
		text := *in
		if b, err := os.ReadFile(*in); err == nil {
			text = string(b)
		}
		emit(cryptan.FreqAnalysis(text), "")
	default:
		fmt.Fprintf(os.Stderr, "cryptan: unknown subcommand %q\n", sub)
		os.Exit(2)
	}
}

func cmdSysaudit(args []string) {
	fs := flag.NewFlagSet("sysaudit", flag.ExitOnError)
	root := fs.String("root", "/", "root path")
	out := fs.String("out", "", "output JSON report")
	_ = fs.Parse(args)
	emit(sysaudit.Audit(*root), *out)
}

func cmdPhish(args []string) {
	fs := flag.NewFlagSet("phish", flag.ExitOnError)
	u := fs.String("url", "", "target URL or domain")
	out := fs.String("out", "", "output JSON report")
	_ = fs.Parse(args)
	if *u == "" {
		fmt.Fprintln(os.Stderr, "phish: -url required")
		os.Exit(2)
	}
	emit(phish.Analyze(context.Background(), *u), *out)
}

func cmdVulnIntel(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "vulnintel: {cve|packages}")
		os.Exit(2)
	}
	sub := args[0]
	fs := flag.NewFlagSet("vulnintel-"+sub, flag.ExitOnError)
	switch sub {
	case "cve":
		id := fs.String("id", "", "CVE ID like CVE-2024-3094")
		out := fs.String("out", "", "output")
		_ = fs.Parse(args[1:])
		if *id == "" {
			fmt.Fprintln(os.Stderr, "vulnintel cve: -id required")
			os.Exit(2)
		}
		emit(vulnintel.LookupCVE(context.Background(), *id), *out)
	case "packages":
		out := fs.String("out", "", "output")
		_ = fs.Parse(args[1:])
		emit(vulnintel.ScanPackages(context.Background()), *out)
	default:
		fmt.Fprintf(os.Stderr, "vulnintel: unknown subcommand %q\n", sub)
		os.Exit(2)
	}
}
