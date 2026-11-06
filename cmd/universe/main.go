package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	core "github.com/ollie/phantomfs/internal/universe/core"

	t01 "github.com/ollie/phantomfs/internal/universe/tools/t01_osintcore"
	t02 "github.com/ollie/phantomfs/internal/universe/tools/t02_geoint"
	t03 "github.com/ollie/phantomfs/internal/universe/tools/t03_domaintrace"
	t04 "github.com/ollie/phantomfs/internal/universe/tools/t04_ipintel"
	t05 "github.com/ollie/phantomfs/internal/universe/tools/t05_userfinder"
	t06 "github.com/ollie/phantomfs/internal/universe/tools/t06_mailtrace"
	t07 "github.com/ollie/phantomfs/internal/universe/tools/t07_phototrace"
	t08 "github.com/ollie/phantomfs/internal/universe/tools/t08_socialmap"
	t09 "github.com/ollie/phantomfs/internal/universe/tools/t09_linktrace"
	t10 "github.com/ollie/phantomfs/internal/universe/tools/t10_metatrack"
	t11 "github.com/ollie/phantomfs/internal/universe/tools/t11_breachwatch"
	t12 "github.com/ollie/phantomfs/internal/universe/tools/t12_darkintel"
	t13 "github.com/ollie/phantomfs/internal/universe/tools/t13_certtrace"
	t14 "github.com/ollie/phantomfs/internal/universe/tools/t14_geoarchive"
	t15 "github.com/ollie/phantomfs/internal/universe/tools/t15_entitylink"
	t16 "github.com/ollie/phantomfs/internal/universe/tools/t16_memoryx"
	t17 "github.com/ollie/phantomfs/internal/universe/tools/t17_binarycore"
	t18 "github.com/ollie/phantomfs/internal/universe/tools/t18_evidencevault"
	t19 "github.com/ollie/phantomfs/internal/universe/tools/t19_timelinex"
	t20 "github.com/ollie/phantomfs/internal/universe/tools/t20_intelgraph"
	t22 "github.com/ollie/phantomfs/internal/universe/tools/t22_shadowtrace"
	t23 "github.com/ollie/phantomfs/internal/universe/tools/t23_ghostint"
	t24 "github.com/ollie/phantomfs/internal/universe/tools/t24_entityx"
	t25 "github.com/ollie/phantomfs/internal/universe/tools/t25_geocrypt"
	t26 "github.com/ollie/phantomfs/internal/universe/tools/t26_ipnexus"
	t27 "github.com/ollie/phantomfs/internal/universe/tools/t27_domainx"
	t28 "github.com/ollie/phantomfs/internal/universe/tools/t28_identrace"
	t29 "github.com/ollie/phantomfs/internal/universe/tools/t29_mailscope"
	t30 "github.com/ollie/phantomfs/internal/universe/tools/t30_photontrace"
	t31 "github.com/ollie/phantomfs/internal/universe/tools/t31_forensix"
	t32 "github.com/ollie/phantomfs/internal/universe/tools/t32_malshield"
	t33 "github.com/ollie/phantomfs/internal/universe/tools/t33_packetx"
	t34 "github.com/ollie/phantomfs/internal/universe/tools/t34_vulnintel"
	t35 "github.com/ollie/phantomfs/internal/universe/tools/t35_certnexus"
	t36 "github.com/ollie/phantomfs/internal/universe/tools/t36_l1xcore"
)

const (
	version = "2.0.0"
	author  = "L1ghtXr"
)

const banner = `
  _   _ _   _ _____ _____ _____ ______ _____
 | | | | \ | |_   _|  ___|  ___|  ___/  ___|
 | | | |  \| | | | | |__ | |__ | |__ \____ \
 | | | | . ' | | | |  __||  __||  __| ___) |
 | |_| | |\  |_| |_| |___| |___| |___/____/
  \___/|_| \_|_____\____/\____/\____|_____|
  UNIVERSE ` + version + ` · author ` + author + ` · ` + runtime.Version() + `
  35 tools — no AI, no ML, real algorithms
`

func main() {
	if len(os.Args) < 2 {
		interactive()
		return
	}
	dispatch(os.Args[1], os.Args[2:])
}

func dispatch(cmd string, args []string) {
	core.SafeRun(cmd, func() {
		switch cmd {
		case "osintcore":
			cmdOSINTCORE(args)
		case "geoint":
			cmdGEOINT(args)
		case "domaintrace":
			cmdDomainTrace(args)
		case "ipintel":
			cmdIPIntel(args)
		case "userfinder":
			cmdUserFinder(args)
		case "mailtrace":
			cmdMailTrace(args)
		case "phototrace":
			cmdPhotoTrace(args)
		case "socialmap":
			cmdSocialMap(args)
		case "linktrace":
			cmdLinkTrace(args)
		case "metatrack":
			cmdMetaTrack(args)
		case "breachwatch":
			cmdBreachWatch(args)
		case "darkintel":
			cmdDarkIntel(args)
		case "certtrace":
			cmdCertTrace(args)
		case "geoarchive":
			cmdGeoArchive(args)
		case "entitylink":
			cmdEntityLink(args)
		case "memoryx":
			cmdMemoryX(args)
		case "binarycore":
			cmdBinaryCore(args)
		case "evidencevault":
			cmdEvidenceVault(args)
		case "timelinex":
			cmdTimelineX(args)
		case "intelgraph":
			cmdIntelGraph(args)
		case "shadowtrace":
			cmdShadowTrace(args)
		case "ghostint":
			cmdGhostInt(args)
		case "entityx":
			cmdEntityX(args)
		case "geocrypt":
			cmdGeoCrypt(args)
		case "ipnexus":
			cmdIPNexus(args)
		case "domainx":
			cmdDomainX(args)
		case "identrace":
			cmdIDentrace(args)
		case "mailscope":
			cmdMailScope(args)
		case "photontrace":
			cmdPhotonTrace(args)
		case "forensix":
			cmdForenSix(args)
		case "malshield":
			cmdMalShield(args)
		case "packetx":
			cmdPacketX(args)
		case "vulnintel":
			cmdVulnIntel(args)
		case "certnexus":
			cmdCertNexus(args)
		case "l1xcore":
			cmdL1XCore(args)
		case "version", "-v", "--version":
			fmt.Printf("universe v%s — author %s\n", version, author)
		case "help", "-h", "--help":
			help()
		case "exit", "quit":
			os.Exit(0)
		default:
			fmt.Fprintf(os.Stderr, "unknown: %s\n", cmd)
			help()
			os.Exit(2)
		}
	})
}

func help() {
	fmt.Print(banner)
	fmt.Printf(`
author: %s

intel & recon:
  osintcore     -target <any>
  geoint        {-ip X|-coords lat,lng|-image file}
  domaintrace   -domain example.com
  ipintel       -ip 1.1.1.1
  userfinder    -user <name>
  mailtrace     -email a@b.com
  linktrace     -url <url>

media forensics:
  phototrace    -file photo.jpg [-deep]
  metatrack     -file <any>

people & entities:
  socialmap     -user <name>
  entitylink    -target <name/email/domain/ip>

threat & breach:
  breachwatch   -email a@b.com | -domain example.com
  darkintel     -ioc <value> | -feed urlhaus
  certtrace     -domain example.com
  geoarchive    {-coords lat,lng|-place <name>}

forensics:
  memoryx       -file mem.dump [-min 6]
  binarycore    -file sample.exe
  evidencevault {init|add|verify|list} -vault ./vault [...]
  timelinex     -in f1.json,f2.log [-from TS] [-to TS]
  intelgraph    -in r1.json,r2.json -format dot -out graph.dot

batch 2:
  shadowtrace   -target <domain|email|user>
  ghostint      -ioc ip,domain,hash [-feed all]
  entityx       -in f1.txt,f2.json [-min 2]
  geocrypt      -coords lat,lng [-from a -to b] [-when RFC3339] [-image photo.jpg]
  ipnexus       -ip 8.8.8.8

batch 3:
  domainx       -domain example.com
  identrace     -user <name> [-email a@b.com]
  mailscope     -file msg.eml
  photontrace   {-url X|-file photo.jpg} [-compare other.jpg]
  forensix      [-root ~] [-recent-days 7]

batch 4:
  malshield     -file sample.exe
  packetx       -file capture.pcap
  vulnintel     {cve|batch|banner} [...]
  certnexus     -domain example.com
  l1xcore       -target <any>

  version, help
`, author)
}

func interactive() {
	fmt.Println(banner)
	sc := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("universe> ")
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
		"tool": r.Tool, "target": r.Target, "author": author,
		"summary": r.Summary(), "findings": r.Findings, "extra": r.Extra,
	}, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal failed: %v\n", err)
		os.Exit(1)
	}
	os.Stdout.Write(b)
	os.Stdout.Write([]byte("\n"))
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ── batch 0 (t01–t15) ────────────────────────────────────────────

func cmdOSINTCORE(args []string) {
	fs := flag.NewFlagSet("osintcore", flag.ExitOnError)
	target := fs.String("target", "", "target")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *target == "" {
		fmt.Fprintln(os.Stderr, "osintcore: -target required")
		os.Exit(2)
	}
	r, err := t01.Run(*target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdGEOINT(args []string) {
	fs := flag.NewFlagSet("geoint", flag.ExitOnError)
	ip := fs.String("ip", "", "IP")
	coords := fs.String("coords", "", "lat,lng")
	img := fs.String("image", "", "image with GPS EXIF")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	r, err := t02.Run(t02.Options{IP: *ip, Coords: *coords, Image: *img})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdDomainTrace(args []string) {
	fs := flag.NewFlagSet("domaintrace", flag.ExitOnError)
	domain := fs.String("domain", "", "apex domain")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *domain == "" {
		fmt.Fprintln(os.Stderr, "domaintrace: -domain required")
		os.Exit(2)
	}
	r, err := t03.Run(*domain)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdIPIntel(args []string) {
	fs := flag.NewFlagSet("ipintel", flag.ExitOnError)
	ip := fs.String("ip", "", "IP")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *ip == "" {
		fmt.Fprintln(os.Stderr, "ipintel: -ip required")
		os.Exit(2)
	}
	r, err := t04.Run(*ip)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdUserFinder(args []string) {
	fs := flag.NewFlagSet("userfinder", flag.ExitOnError)
	user := fs.String("user", "", "username")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *user == "" {
		fmt.Fprintln(os.Stderr, "userfinder: -user required")
		os.Exit(2)
	}
	r, err := t05.Run(*user)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdMailTrace(args []string) {
	fs := flag.NewFlagSet("mailtrace", flag.ExitOnError)
	email := fs.String("email", "", "email")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *email == "" {
		fmt.Fprintln(os.Stderr, "mailtrace: -email required")
		os.Exit(2)
	}
	r, err := t06.Run(*email)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdPhotoTrace(args []string) {
	fs := flag.NewFlagSet("phototrace", flag.ExitOnError)
	file := fs.String("file", "", "image file")
	deep := fs.Bool("deep", false, "run deep analyses")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *file == "" {
		fmt.Fprintln(os.Stderr, "phototrace: -file required")
		os.Exit(2)
	}
	r, err := t07.Run(*file, t07.Options{Deep: *deep})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdSocialMap(args []string) {
	fs := flag.NewFlagSet("socialmap", flag.ExitOnError)
	user := fs.String("user", "", "username")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *user == "" {
		fmt.Fprintln(os.Stderr, "socialmap: -user required")
		os.Exit(2)
	}
	r, err := t08.Run(*user)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdLinkTrace(args []string) {
	fs := flag.NewFlagSet("linktrace", flag.ExitOnError)
	url := fs.String("url", "", "URL")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *url == "" {
		fmt.Fprintln(os.Stderr, "linktrace: -url required")
		os.Exit(2)
	}
	r, err := t09.Run(*url)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdMetaTrack(args []string) {
	fs := flag.NewFlagSet("metatrack", flag.ExitOnError)
	file := fs.String("file", "", "file")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *file == "" {
		fmt.Fprintln(os.Stderr, "metatrack: -file required")
		os.Exit(2)
	}
	r, err := t10.Run(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdBreachWatch(args []string) {
	fs := flag.NewFlagSet("breachwatch", flag.ExitOnError)
	email := fs.String("email", "", "email")
	domain := fs.String("domain", "", "domain")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	r, err := t11.Run(*email, *domain)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdDarkIntel(args []string) {
	fs := flag.NewFlagSet("darkintel", flag.ExitOnError)
	ioc := fs.String("ioc", "", "IOC")
	feed := fs.String("feed", "", "urlhaus|threatfox|feodo|openphish")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	r, err := t12.Run(*ioc, *feed)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdCertTrace(args []string) {
	fs := flag.NewFlagSet("certtrace", flag.ExitOnError)
	domain := fs.String("domain", "", "domain")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *domain == "" {
		fmt.Fprintln(os.Stderr, "certtrace: -domain required")
		os.Exit(2)
	}
	r, err := t13.Run(*domain)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdGeoArchive(args []string) {
	fs := flag.NewFlagSet("geoarchive", flag.ExitOnError)
	coords := fs.String("coords", "", "lat,lng")
	place := fs.String("place", "", "place name")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	r, err := t14.Run(*coords, *place)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdEntityLink(args []string) {
	fs := flag.NewFlagSet("entitylink", flag.ExitOnError)
	target := fs.String("target", "", "target")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *target == "" {
		fmt.Fprintln(os.Stderr, "entitylink: -target required")
		os.Exit(2)
	}
	r, err := t15.Run(*target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

// ── batch 1 (t16–t20) ────────────────────────────────────────────

func cmdMemoryX(args []string) {
	fs := flag.NewFlagSet("memoryx", flag.ExitOnError)
	file := fs.String("file", "", "memory dump")
	min := fs.Int("min", 4, "min string length")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *file == "" {
		fmt.Fprintln(os.Stderr, "memoryx: -file required")
		os.Exit(2)
	}
	r, err := t16.Run(*file, t16.Options{MinString: *min})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdBinaryCore(args []string) {
	fs := flag.NewFlagSet("binarycore", flag.ExitOnError)
	file := fs.String("file", "", "binary")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *file == "" {
		fmt.Fprintln(os.Stderr, "binarycore: -file required")
		os.Exit(2)
	}
	r, err := t17.Run(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdEvidenceVault(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "evidencevault: {init|add|verify|list}")
		os.Exit(2)
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("evidencevault-"+sub, flag.ExitOnError)
	vault := fs.String("vault", "./vault", "vault directory")
	out := fs.String("out", "", "output")
	switch sub {
	case "init":
		_ = fs.Parse(rest)
		r, err := t18.Init(*vault)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		emit(r, *out)
	case "add":
		file := fs.String("file", "", "evidence file")
		label := fs.String("label", "", "label")
		_ = fs.Parse(rest)
		if *file == "" {
			fmt.Fprintln(os.Stderr, "add: -file required")
			os.Exit(2)
		}
		r, err := t18.Add(*vault, *file, *label)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		emit(r, *out)
	case "verify":
		_ = fs.Parse(rest)
		r, err := t18.Verify(*vault)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		emit(r, *out)
	case "list":
		_ = fs.Parse(rest)
		r, err := t18.List(*vault)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		emit(r, *out)
	default:
		fmt.Fprintf(os.Stderr, "evidencevault: unknown %q\n", sub)
		os.Exit(2)
	}
}

func cmdTimelineX(args []string) {
	fs := flag.NewFlagSet("timelinex", flag.ExitOnError)
	in := fs.String("in", "", "comma-separated inputs")
	from := fs.String("from", "", "RFC3339 lower bound")
	to := fs.String("to", "", "RFC3339 upper bound")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *in == "" {
		fmt.Fprintln(os.Stderr, "timelinex: -in required")
		os.Exit(2)
	}
	r, err := t19.Run(t19.Options{Inputs: splitCSV(*in), From: *from, To: *to})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdIntelGraph(args []string) {
	fs := flag.NewFlagSet("intelgraph", flag.ExitOnError)
	in := fs.String("in", "", "comma-separated JSON reports")
	format := fs.String("format", "dot", "dot|json|text")
	out := fs.String("out", "", "output file")
	_ = fs.Parse(args)
	if *in == "" {
		fmt.Fprintln(os.Stderr, "intelgraph: -in required")
		os.Exit(2)
	}
	r, err := t20.Run(splitCSV(*in), *format, *out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, "")
}

// ── batch 2 (t22–t26) ────────────────────────────────────────────

func cmdShadowTrace(args []string) {
	fs := flag.NewFlagSet("shadowtrace", flag.ExitOnError)
	target := fs.String("target", "", "domain|email|user")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *target == "" {
		fmt.Fprintln(os.Stderr, "shadowtrace: -target required")
		os.Exit(2)
	}
	r, err := t22.Run(*target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdGhostInt(args []string) {
	fs := flag.NewFlagSet("ghostint", flag.ExitOnError)
	ioc := fs.String("ioc", "", "comma-separated IOCs")
	feed := fs.String("feed", "", "urlhaus|threatfox|feodo|all")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	r, err := t23.Run(splitCSV(*ioc), *feed)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdEntityX(args []string) {
	fs := flag.NewFlagSet("entityx", flag.ExitOnError)
	in := fs.String("in", "", "comma-separated files")
	min := fs.Int("min", 2, "min co-occurrence")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *in == "" {
		fmt.Fprintln(os.Stderr, "entityx: -in required")
		os.Exit(2)
	}
	r, err := t24.Run(splitCSV(*in), *min)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdGeoCrypt(args []string) {
	fs := flag.NewFlagSet("geocrypt", flag.ExitOnError)
	coords := fs.String("coords", "", "lat,lng")
	img := fs.String("image", "", "image with GPS EXIF")
	from := fs.String("from", "", "source coords")
	to := fs.String("to", "", "dest coords")
	when := fs.String("when", "", "RFC3339")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	r, err := t25.Run(t25.Options{Coords: *coords, Image: *img, From: *from, To: *to, When: *when})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdIPNexus(args []string) {
	fs := flag.NewFlagSet("ipnexus", flag.ExitOnError)
	ip := fs.String("ip", "", "IP address")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *ip == "" {
		fmt.Fprintln(os.Stderr, "ipnexus: -ip required")
		os.Exit(2)
	}
	r, err := t26.Run(*ip)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

// ── batch 3 (t27–t31) ────────────────────────────────────────────

func cmdDomainX(args []string) {
	fs := flag.NewFlagSet("domainx", flag.ExitOnError)
	domain := fs.String("domain", "", "apex domain")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *domain == "" {
		fmt.Fprintln(os.Stderr, "domainx: -domain required")
		os.Exit(2)
	}
	r, err := t27.Run(*domain)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdIDentrace(args []string) {
	fs := flag.NewFlagSet("identrace", flag.ExitOnError)
	user := fs.String("user", "", "username")
	email := fs.String("email", "", "email")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *user == "" && *email == "" {
		fmt.Fprintln(os.Stderr, "identrace: -user or -email required")
		os.Exit(2)
	}
	r, err := t28.Run(*user, *email)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdMailScope(args []string) {
	fs := flag.NewFlagSet("mailscope", flag.ExitOnError)
	file := fs.String("file", "", "raw email .eml")
	out := fs.String("out", "", "JSON report")
	verify := fs.Bool("verify", true, "verify DKIM/SPF/DMARC")
	_ = fs.Parse(args)
	if *file == "" {
		fmt.Fprintln(os.Stderr, "mailscope: -file required")
		os.Exit(2)
	}
	r, err := t29.Run(*file, t29.Options{Verify: *verify})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdPhotonTrace(args []string) {
	fs := flag.NewFlagSet("photontrace", flag.ExitOnError)
	url := fs.String("url", "", "image URL")
	file := fs.String("file", "", "local image")
	compare := fs.String("compare", "", "compare file")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	r, err := t30.Run(t30.Options{URL: *url, File: *file, Compare: *compare})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdForenSix(args []string) {
	fs := flag.NewFlagSet("forensix", flag.ExitOnError)
	root := fs.String("root", "", "root dir")
	recent := fs.Int("recent-days", 7, "recent window")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	r, err := t31.Run(t31.Options{Root: *root, RecentDays: *recent})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

// ── batch 4 (t32–t36) ────────────────────────────────────────────

func cmdMalShield(args []string) {
	fs := flag.NewFlagSet("malshield", flag.ExitOnError)
	file := fs.String("file", "", "binary")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *file == "" {
		fmt.Fprintln(os.Stderr, "malshield: -file required")
		os.Exit(2)
	}
	r, err := t32.Run(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdPacketX(args []string) {
	fs := flag.NewFlagSet("packetx", flag.ExitOnError)
	file := fs.String("file", "", "pcap file")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *file == "" {
		fmt.Fprintln(os.Stderr, "packetx: -file required")
		os.Exit(2)
	}
	r, err := t33.Run(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdVulnIntel(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "vulnintel: {cve|batch|banner}")
		os.Exit(2)
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("vulnintel-"+sub, flag.ExitOnError)
	out := fs.String("out", "", "output")
	switch sub {
	case "cve":
		id := fs.String("id", "", "CVE ID")
		_ = fs.Parse(rest)
		if *id == "" {
			fmt.Fprintln(os.Stderr, "cve: -id required")
			os.Exit(2)
		}
		r, err := t34.Lookup(*id)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		emit(r, *out)
	case "batch":
		f := fs.String("file", "", "file of CVE IDs")
		_ = fs.Parse(rest)
		if *f == "" {
			fmt.Fprintln(os.Stderr, "batch: -file required")
			os.Exit(2)
		}
		r, err := t34.Batch(*f)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		emit(r, *out)
	case "banner":
		b := fs.String("banner", "", "service banner")
		_ = fs.Parse(rest)
		if *b == "" {
			fmt.Fprintln(os.Stderr, "banner: -banner required")
			os.Exit(2)
		}
		r, err := t34.FromBanner(*b)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		emit(r, *out)
	default:
		fmt.Fprintf(os.Stderr, "vulnintel: unknown %q\n", sub)
		os.Exit(2)
	}
}

func cmdCertNexus(args []string) {
	fs := flag.NewFlagSet("certnexus", flag.ExitOnError)
	domain := fs.String("domain", "", "domain")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *domain == "" {
		fmt.Fprintln(os.Stderr, "certnexus: -domain required")
		os.Exit(2)
	}
	r, err := t35.Run(*domain)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdL1XCore(args []string) {
	fs := flag.NewFlagSet("l1xcore", flag.ExitOnError)
	target := fs.String("target", "", "target")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *target == "" {
		fmt.Fprintln(os.Stderr, "l1xcore: -target required")
		os.Exit(2)
	}
	r, err := t36.Run(*target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}
