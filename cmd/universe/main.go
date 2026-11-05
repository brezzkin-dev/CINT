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
	"github.com/ollie/phantomfs/internal/universe/tools/t01_osintcore"
	"github.com/ollie/phantomfs/internal/universe/tools/t02_geoint"
	"github.com/ollie/phantomfs/internal/universe/tools/t03_domaintrace"
	"github.com/ollie/phantomfs/internal/universe/tools/t04_ipintel"
	"github.com/ollie/phantomfs/internal/universe/tools/t05_userfinder"
	"github.com/ollie/phantomfs/internal/universe/tools/t06_mailtrace"
	"github.com/ollie/phantomfs/internal/universe/tools/t07_phototrace"
	"github.com/ollie/phantomfs/internal/universe/tools/t08_socialmap"
	"github.com/ollie/phantomfs/internal/universe/tools/t09_linktrace"
	"github.com/ollie/phantomfs/internal/universe/tools/t10_metatrack"
	"github.com/ollie/phantomfs/internal/universe/tools/t11_breachwatch"
	"github.com/ollie/phantomfs/internal/universe/tools/t12_darkintel"
	"github.com/ollie/phantomfs/internal/universe/tools/t13_certtrace"
	"github.com/ollie/phantomfs/internal/universe/tools/t14_geoarchive"
	"github.com/ollie/phantomfs/internal/universe/tools/t15_entitylink"
	t16_memoryx "github.com/ollie/phantomfs/internal/universe/tools/t16_memoryx"
	t17_binarycore "github.com/ollie/phantomfs/internal/universe/tools/t17_binarycore"
	t18_evidencevault "github.com/ollie/phantomfs/internal/universe/tools/t18_evidencevault"
	t19_timelinex "github.com/ollie/phantomfs/internal/universe/tools/t19_timelinex"
	t20_intelgraph "github.com/ollie/phantomfs/internal/universe/tools/t20_intelgraph"
	t22_shadowtrace "github.com/ollie/phantomfs/internal/universe/tools/t22_shadowtrace"
	t23_ghostint "github.com/ollie/phantomfs/internal/universe/tools/t23_ghostint"
	t24_entityx "github.com/ollie/phantomfs/internal/universe/tools/t24_entityx"
	t25_geocrypt "github.com/ollie/phantomfs/internal/universe/tools/t25_geocrypt"
	t26_ipnexus "github.com/ollie/phantomfs/internal/universe/tools/t26_ipnexus"
)

const (
	version = "1.0.0"
	author  = "L1ghtXr"
)

var banner = `
  _   _ _   _ _____ _____ _____ ______ _____
 | | | | \ | |_   _|  ___|  ___|  ___/  ___|
 | | | |  \| | | | | |__ | |__ | |__ \____ \
 | | | | . ' | | | |  __||  __||  __| ___) |
 | |_| | |\  |_| |_| |___| |___| |___/____/
  \___/|_| \_|_____\____/\____/\____|_____|
  UNIVERSE ` + version + ` · author ` + author + ` · ` + runtime.Version() + `
  15 OSINT tools — no AI, no ML, real algorithms
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
		case "version", "-v", "--version":
			fmt.Printf("universe v%s — author %s\n", version, author)
		case "help", "-h", "--help":
			help()
		case "exit", "quit":
			os.Exit(0)
		default:
			fmt.Fprintf(os.Stderr, "unknown: %s\n", cmd)
			help()
			os.Exit(1)
		}
	})
}

func help() {
	fmt.Print(banner)
	fmt.Printf(`
author: %s

  osintcore   -target <any>
  geoint      {-ip X|-coords lat,lng|-image file}
  domaintrace -domain example.com
  ipintel     -ip 1.1.1.1
  userfinder  -user <name>
  mailtrace   -email a@b.com
  phototrace  -file photo.jpg [-deep]
  socialmap   -user <name>
  linktrace   -url <url>
  metatrack   -file <any>
  breachwatch {-email a@b.com|-domain example.com}
  darkintel   {-ioc <value>|-feed urlhaus|feodo}
  certtrace   -domain example.com
  geoarchive  {-coords lat,lng|-place <name>}
  entitylink  -target <name/email/domain/ip>

forensics batch:
  memoryx        -file dump.raw [-min 4]
  binarycore     -file sample.exe
  evidencevault  {init|add|verify|list} -vault ./vault [-file X -label L]
  timelinex      -in f1,f2 [-from RFC3339] [-to RFC3339]
  intelgraph     -in r1.json,r2.json [-format dot|json|text] [-out graph.dot]

osint batch 2:
  shadowtrace    -target <domain|email|user>
  ghostint       -ioc a,b,c [-feed urlhaus|threatfox|feodo|all]
  entityx        -in f1,f2 [-min 2]
  geocrypt       -coords lat,lng | -image photo.jpg [-from lat,lng -to lat,lng] [-when RFC3339]
  ipnexus        -ip <addr>

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
		_ = r.SaveJSON(out)
		fmt.Fprintf(os.Stderr, "saved: %s\n", out)
	}
	b, _ := json.MarshalIndent(map[string]any{
		"tool": r.Tool, "target": r.Target, "author": author,
		"summary": r.Summary(), "findings": r.Findings, "extra": r.Extra,
	}, "", "  ")
	os.Stdout.Write(b)
	os.Stdout.Write([]byte("\n"))
}

func cmdOSINTCORE(args []string) {
	fs := flag.NewFlagSet("osintcore", flag.ExitOnError)
	target := fs.String("target", "", "any target")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *target == "" {
		fmt.Fprintln(os.Stderr, "osintcore: -target required")
		os.Exit(1)
	}
	r, err := t01_osintcore.Run(*target)
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
	out := fs.String("out", "", "JSON")
	_ = fs.Parse(args)
	r, err := t02_geoint.Run(t02_geoint.Options{IP: *ip, Coords: *coords, Image: *img})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdDomainTrace(args []string) {
	fs := flag.NewFlagSet("domaintrace", flag.ExitOnError)
	domain := fs.String("domain", "", "apex domain")
	out := fs.String("out", "", "JSON")
	_ = fs.Parse(args)
	if *domain == "" {
		fmt.Fprintln(os.Stderr, "domaintrace: -domain required")
		os.Exit(1)
	}
	r, err := t03_domaintrace.Run(*domain)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdIPIntel(args []string) {
	fs := flag.NewFlagSet("ipintel", flag.ExitOnError)
	ip := fs.String("ip", "", "IP")
	out := fs.String("out", "", "JSON")
	_ = fs.Parse(args)
	if *ip == "" {
		fmt.Fprintln(os.Stderr, "ipintel: -ip required")
		os.Exit(1)
	}
	r, err := t04_ipintel.Run(*ip)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdUserFinder(args []string) {
	fs := flag.NewFlagSet("userfinder", flag.ExitOnError)
	user := fs.String("user", "", "username")
	out := fs.String("out", "", "JSON")
	_ = fs.Parse(args)
	if *user == "" {
		fmt.Fprintln(os.Stderr, "userfinder: -user required")
		os.Exit(1)
	}
	r, err := t05_userfinder.Run(*user)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdMailTrace(args []string) {
	fs := flag.NewFlagSet("mailtrace", flag.ExitOnError)
	email := fs.String("email", "", "email address")
	out := fs.String("out", "", "JSON")
	_ = fs.Parse(args)
	if *email == "" {
		fmt.Fprintln(os.Stderr, "mailtrace: -email required")
		os.Exit(1)
	}
	r, err := t06_mailtrace.Run(*email)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdPhotoTrace(args []string) {
	fs := flag.NewFlagSet("phototrace", flag.ExitOnError)
	file := fs.String("file", "", "image file")
	deep := fs.Bool("deep", false, "run all pixel analyses")
	out := fs.String("out", "", "JSON")
	_ = fs.Parse(args)
	if *file == "" {
		fmt.Fprintln(os.Stderr, "phototrace: -file required")
		os.Exit(1)
	}
	r, err := t07_phototrace.Run(*file, t07_phototrace.Options{Deep: *deep})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdSocialMap(args []string) {
	fs := flag.NewFlagSet("socialmap", flag.ExitOnError)
	user := fs.String("user", "", "username")
	out := fs.String("out", "", "JSON")
	_ = fs.Parse(args)
	if *user == "" {
		fmt.Fprintln(os.Stderr, "socialmap: -user required")
		os.Exit(1)
	}
	r, err := t08_socialmap.Run(*user)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdLinkTrace(args []string) {
	fs := flag.NewFlagSet("linktrace", flag.ExitOnError)
	u := fs.String("url", "", "URL")
	out := fs.String("out", "", "JSON")
	_ = fs.Parse(args)
	if *u == "" {
		fmt.Fprintln(os.Stderr, "linktrace: -url required")
		os.Exit(1)
	}
	r, err := t09_linktrace.Run(*u)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdMetaTrack(args []string) {
	fs := flag.NewFlagSet("metatrack", flag.ExitOnError)
	file := fs.String("file", "", "file")
	out := fs.String("out", "", "JSON")
	_ = fs.Parse(args)
	if *file == "" {
		fmt.Fprintln(os.Stderr, "metatrack: -file required")
		os.Exit(1)
	}
	r, err := t10_metatrack.Run(*file)
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
	out := fs.String("out", "", "JSON")
	_ = fs.Parse(args)
	r, err := t11_breachwatch.Run(*email, *domain)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdDarkIntel(args []string) {
	fs := flag.NewFlagSet("darkintel", flag.ExitOnError)
	ioc := fs.String("ioc", "", "IOC")
	feed := fs.String("feed", "", "feed: urlhaus|threatfox|feodo")
	out := fs.String("out", "", "JSON")
	_ = fs.Parse(args)
	r, err := t12_darkintel.Run(*ioc, *feed)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdCertTrace(args []string) {
	fs := flag.NewFlagSet("certtrace", flag.ExitOnError)
	domain := fs.String("domain", "", "domain")
	out := fs.String("out", "", "JSON")
	_ = fs.Parse(args)
	if *domain == "" {
		fmt.Fprintln(os.Stderr, "certtrace: -domain required")
		os.Exit(1)
	}
	r, err := t13_certtrace.Run(*domain)
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
	out := fs.String("out", "", "JSON")
	_ = fs.Parse(args)
	r, err := t14_geoarchive.Run(*coords, *place)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdEntityLink(args []string) {
	fs := flag.NewFlagSet("entitylink", flag.ExitOnError)
	target := fs.String("target", "", "target entity")
	out := fs.String("out", "", "JSON")
	_ = fs.Parse(args)
	if *target == "" {
		fmt.Fprintln(os.Stderr, "entitylink: -target required")
		os.Exit(1)
	}
	r, err := t15_entitylink.Run(*target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdMemoryX(args []string) {
	fs := flag.NewFlagSet("memoryx", flag.ExitOnError)
	file := fs.String("file", "", "memory dump")
	out := fs.String("out", "", "JSON report")
	min := fs.Int("min", 4, "min string length")
	_ = fs.Parse(args)
	if *file == "" {
		fmt.Fprintln(os.Stderr, "memoryx: -file required")
		os.Exit(1)
	}
	r, err := t16_memoryx.Run(*file, t16_memoryx.Options{MinString: *min})
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
		os.Exit(1)
	}
	r, err := t17_binarycore.Run(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdEvidenceVault(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "evidencevault: {init|add|verify|list} [flags]")
		os.Exit(1)
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("evidencevault-"+sub, flag.ExitOnError)
	vault := fs.String("vault", "./vault", "vault directory")
	out := fs.String("out", "", "output JSON")
	switch sub {
	case "init":
		_ = fs.Parse(rest)
		r, err := t18_evidencevault.Init(*vault)
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
			os.Exit(1)
		}
		r, err := t18_evidencevault.Add(*vault, *file, *label)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		emit(r, *out)
	case "verify":
		_ = fs.Parse(rest)
		r, err := t18_evidencevault.Verify(*vault)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		emit(r, *out)
	case "list":
		_ = fs.Parse(rest)
		r, err := t18_evidencevault.List(*vault)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		emit(r, *out)
	}
}

func cmdTimelineX(args []string) {
	fs := flag.NewFlagSet("timelinex", flag.ExitOnError)
	inputs := fs.String("in", "", "comma-separated files/dirs")
	from := fs.String("from", "", "RFC3339 lower bound")
	to := fs.String("to", "", "RFC3339 upper bound")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *inputs == "" {
		fmt.Fprintln(os.Stderr, "timelinex: -in required")
		os.Exit(1)
	}
	r, err := t19_timelinex.Run(t19_timelinex.Options{
		Inputs: splitCSV(*inputs), From: *from, To: *to,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdIntelGraph(args []string) {
	fs := flag.NewFlagSet("intelgraph", flag.ExitOnError)
	inputs := fs.String("in", "", "comma-separated JSON reports")
	format := fs.String("format", "dot", "dot|json|text")
	out := fs.String("out", "", "output file (empty = stdout)")
	_ = fs.Parse(args)
	if *inputs == "" {
		fmt.Fprintln(os.Stderr, "intelgraph: -in required")
		os.Exit(1)
	}
	r, err := t20_intelgraph.Run(splitCSV(*inputs), *format, *out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, "")
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

func cmdShadowTrace(args []string) {
	fs := flag.NewFlagSet("shadowtrace", flag.ExitOnError)
	target := fs.String("target", "", "domain | email | username")
	out := fs.String("out", "", "JSON")
	_ = fs.Parse(args)
	if *target == "" {
		fmt.Fprintln(os.Stderr, "shadowtrace: -target required")
		os.Exit(1)
	}
	r, err := t22_shadowtrace.Run(*target)
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
	out := fs.String("out", "", "JSON")
	_ = fs.Parse(args)
	r, err := t23_ghostint.Run(splitCSV(*ioc), *feed)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdEntityX(args []string) {
	fs := flag.NewFlagSet("entityx", flag.ExitOnError)
	in := fs.String("in", "", "comma-separated text/JSON files")
	out := fs.String("out", "", "JSON")
	minCount := fs.Int("min", 2, "min co-occurrence count for edge")
	_ = fs.Parse(args)
	if *in == "" {
		fmt.Fprintln(os.Stderr, "entityx: -in required")
		os.Exit(1)
	}
	r, err := t24_entityx.Run(splitCSV(*in), *minCount)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdGeoCrypt(args []string) {
	fs := flag.NewFlagSet("geocrypt", flag.ExitOnError)
	coords := fs.String("coords", "", "lat,lng")
	image := fs.String("image", "", "image with GPS EXIF")
	from := fs.String("from", "", "source coords lat,lng")
	to := fs.String("to", "", "dest coords lat,lng")
	when := fs.String("when", "", "RFC3339 for sun position")
	out := fs.String("out", "", "JSON")
	_ = fs.Parse(args)
	r, err := t25_geocrypt.Run(t25_geocrypt.Options{
		Coords: *coords, Image: *image, From: *from, To: *to, When: *when,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdIPNexus(args []string) {
	fs := flag.NewFlagSet("ipnexus", flag.ExitOnError)
	ip := fs.String("ip", "", "IP address")
	out := fs.String("out", "", "JSON")
	_ = fs.Parse(args)
	if *ip == "" {
		fmt.Fprintln(os.Stderr, "ipnexus: -ip required")
		os.Exit(1)
	}
	r, err := t26_ipnexus.Run(*ip)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

