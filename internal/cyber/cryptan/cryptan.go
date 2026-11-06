// Package cryptan — Cryptographic Analysis.
package cryptan

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ollie/phantomfs/internal/cyber/core"
)

func IdentifyHash(h string) (string, string) {
	h = strings.TrimSpace(h)
	switch {
	case len(h) == 32 && isHex(h):
		return "MD5", "fast"
	case len(h) == 40 && isHex(h):
		return "SHA1", "fast"
	case len(h) == 64 && isHex(h):
		return "SHA256", "medium"
	case len(h) == 128 && isHex(h):
		return "SHA512", "medium"
	case strings.HasPrefix(h, "$2a$") || strings.HasPrefix(h, "$2b$") || strings.HasPrefix(h, "$2y$"):
		return "bcrypt", "slow"
	case strings.HasPrefix(h, "$argon2"):
		return "argon2", "slow"
	case strings.HasPrefix(h, "$1$"):
		return "MD5-crypt", "fast"
	case strings.HasPrefix(h, "$5$"):
		return "SHA256-crypt", "medium"
	case strings.HasPrefix(h, "$6$"):
		return "SHA512-crypt", "medium"
	}
	return "unknown", "unknown"
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func computeHash(algo string, s []byte) string {
	switch algo {
	case "MD5":
		h := md5.Sum(s)
		return hex.EncodeToString(h[:])
	case "SHA1":
		h := sha1.Sum(s)
		return hex.EncodeToString(h[:])
	case "SHA256":
		h := sha256.Sum256(s)
		return hex.EncodeToString(h[:])
	case "SHA512":
		h := sha512.Sum512(s)
		return hex.EncodeToString(h[:])
	}
	return ""
}

func Crack(hash string, wordlistPath string) *core.Result {
	r := core.NewResult("cryptan-crack", hash)
	algo, _ := IdentifyHash(hash)
	r.AddExtra("algo", algo)
	if algo == "unknown" {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevMed, Title: "unknown hash format"})
		r.Finish()
		return r
	}
	f, err := os.Open(wordlistPath)
	if err != nil {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevHigh, Title: "wordlist not readable", Detail: err.Error()})
		r.Finish()
		return r
	}
	defer f.Close()

	target := strings.ToLower(hash)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024), 1024*1024)
	var tried int
	for sc.Scan() {
		word := strings.TrimRight(sc.Text(), "\r\n")
		tried++
		h := computeHash(algo, []byte(word))
		if subtle.ConstantTimeCompare([]byte(h), []byte(target)) == 1 {
			r.Add(core.Finding{
				Tool: "cryptan", Severity: core.SevHigh,
				Title:    "hash cracked",
				Detail:   fmt.Sprintf("%q (%d attempts)", word, tried),
				Evidence: map[string]any{"plaintext": word, "attempts": tried},
			})
			r.Finish()
			return r
		}
	}
	r.AddExtra("attempts", tried)
	r.Finish()
	return r
}

func DecodeJWT(token string) *core.Result {
	r := core.NewResult("cryptan-jwt", "")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevHigh, Title: "not a JWT (expected 3 segments)"})
		r.Finish()
		return r
	}
	hdr, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	body, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevHigh, Title: "decode error"})
		r.Finish()
		return r
	}
	var hdrObj, bodyObj map[string]any
	json.Unmarshal(hdr, &hdrObj)
	json.Unmarshal(body, &bodyObj)
	r.AddExtra("header", hdrObj)
	r.AddExtra("payload", bodyObj)
	r.AddExtra("signature_hex", hex.EncodeToString(sig))

	if alg, ok := hdrObj["alg"].(string); ok {
		switch alg {
		case "none":
			r.Add(core.Finding{Tool: "cryptan", Severity: core.SevCrit, Title: "alg=none — unsigned JWT"})
		case "HS256", "HS384", "HS512":
			r.Add(core.Finding{Tool: "cryptan", Severity: core.SevMed,
				Title: "HMAC-signed JWT (verify secret strength)"})
		case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512":
			r.Add(core.Finding{Tool: "cryptan", Severity: core.SevInfo,
				Title: "Asymmetric JWT (" + alg + ")"})
		}
	}
	r.Finish()
	return r
}

func AESCrypt(encrypt bool, keyHex, inputPath, outputPath string) error {
	key, err := hex.DecodeString(keyHex)
	if err != nil || (len(key) != 16 && len(key) != 24 && len(key) != 32) {
		return fmt.Errorf("key must be 16/24/32 bytes hex")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	input, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	if encrypt {
		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return err
		}
		out := gcm.Seal(nonce, nonce, input, nil)
		return os.WriteFile(outputPath, out, 0644)
	}
	ns := gcm.NonceSize()
	if len(input) < ns {
		return fmt.Errorf("ciphertext too short")
	}
	nonce, ct := input[:ns], input[ns:]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, plain, 0644)
}

func FreqAnalysis(s string) *core.Result {
	r := core.NewResult("cryptan-freq", "")
	counts := map[rune]int{}
	total := 0
	for _, c := range strings.ToUpper(s) {
		if c >= 'A' && c <= 'Z' {
			counts[c]++
			total++
		}
	}
	if total == 0 {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevHigh, Title: "no alphabetic content"})
		r.Finish()
		return r
	}
	freq := map[string]float64{}
	for k, v := range counts {
		freq[string(k)] = float64(v) / float64(total) * 100
	}
	r.AddExtra("total_letters", total)
	r.AddExtra("frequency_pct", freq)

	english := map[rune]float64{
		'A': 8.17, 'B': 1.49, 'C': 2.78, 'D': 4.25, 'E': 12.70, 'F': 2.23,
		'G': 2.02, 'H': 6.09, 'I': 6.97, 'J': 0.15, 'K': 0.77, 'L': 4.03,
		'M': 2.41, 'N': 6.75, 'O': 7.51, 'P': 1.93, 'Q': 0.10, 'R': 5.99,
		'S': 6.33, 'T': 9.06, 'U': 2.76, 'V': 0.98, 'W': 2.36, 'X': 0.15,
		'Y': 1.97, 'Z': 0.07,
	}
	var chi float64
	for c := 'A'; c <= 'Z'; c++ {
		exp := english[c] / 100 * float64(total)
		obs := float64(counts[c])
		if exp > 0 {
			chi += (obs - exp) * (obs - exp) / exp
		}
	}
	r.AddExtra("chi_square", chi)
	if chi < 50 {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevInfo,
			Title:  "likely English plaintext",
			Detail: fmt.Sprintf("chi-square %.2f", chi)})
	} else {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevMed,
			Title:  "unlikely English (substitution cipher or foreign)",
			Detail: fmt.Sprintf("chi-square %.2f", chi)})
	}
	r.Finish()
	return r
}

// IDResult wraps IdentifyHash into a Result.
func IDResult(h string) *core.Result {
	r := core.NewResult("cryptan-id", h)
	algo, speed := IdentifyHash(h)
	r.AddExtra("algo", algo)
	r.AddExtra("speed", speed)
	r.Finish()
	return r
}

// BreakXOR tries single-byte XOR with chi-square scoring.
func BreakXOR(ct []byte) *core.Result {
	r := core.NewResult("cryptan-xor", "")
	if len(ct) == 0 {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevHigh, Title: "empty ciphertext"})
		r.Finish()
		return r
	}
	bestKey, bestScore := byte(0), 1e18
	var bestPlain []byte
	english := map[byte]float64{
		'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.8,
		'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'U': 2.8,
	}
	for k := 0; k < 256; k++ {
		plain := make([]byte, len(ct))
		for i, c := range ct {
			plain[i] = c ^ byte(k)
		}
		var counts [256]int
		letters := 0
		for _, c := range plain {
			u := c
			if u >= 'a' && u <= 'z' {
				u -= 32
			}
			if u >= 'A' && u <= 'Z' {
				counts[u]++
				letters++
			}
		}
		if letters == 0 {
			continue
		}
		var chi float64
		for b, expPct := range english {
			exp := expPct / 100 * float64(letters)
			obs := float64(counts[b])
			if exp > 0 {
				chi += (obs - exp) * (obs - exp) / exp
			}
		}
		if chi < bestScore {
			bestScore = chi
			bestKey = byte(k)
			bestPlain = plain
		}
	}
	r.AddExtra("key", fmt.Sprintf("0x%02x", bestKey))
	r.AddExtra("chi_square", bestScore)
	preview := string(bestPlain)
	if len(preview) > 200 {
		preview = preview[:200]
	}
	r.AddExtra("plaintext_preview", preview)
	r.Add(core.Finding{Tool: "cryptan", Severity: core.SevHigh,
		Title:  fmt.Sprintf("XOR key 0x%02x (chi=%.1f)", bestKey, bestScore),
		Detail: preview})
	r.Finish()
	return r
}

// BreakVigenere uses IoC for key length then chi-square per column.
func BreakVigenere(ct string) *core.Result {
	r := core.NewResult("cryptan-vig", "")
	letters := make([]byte, 0, len(ct))
	for _, c := range strings.ToUpper(ct) {
		if c >= 'A' && c <= 'Z' {
			letters = append(letters, byte(c))
		}
	}
	if len(letters) < 20 {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevMed, Title: "ciphertext too short"})
		r.Finish()
		return r
	}
	// Find best key length by index of coincidence
	bestLen, bestIOC := 1, 0.0
	for kl := 1; kl <= 20 && kl < len(letters)/2; kl++ {
		var iocSum float64
		cols := 0
		for col := 0; col < kl; col++ {
			var counts [26]int
			n := 0
			for i := col; i < len(letters); i += kl {
				counts[letters[i]-'A']++
				n++
			}
			if n < 2 {
				continue
			}
			var num float64
			for _, c := range counts {
				num += float64(c * (c - 1))
			}
			iocSum += num / float64(n*(n-1))
			cols++
		}
		if cols > 0 {
			avg := iocSum / float64(cols)
			if avg > bestIOC {
				bestIOC = avg
				bestLen = kl
			}
		}
	}
	// Decrypt each column
	key := make([]byte, bestLen)
	englishFreq := []float64{
		8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, 0.15, 0.8, 4.0, 2.4,
		6.8, 7.5, 1.9, 0.1, 6.0, 6.3, 9.1, 2.8, 1.0, 2.4, 0.15, 2.0, 0.07,
	}
	for col := 0; col < bestLen; col++ {
		bestShift, bestChi := 0, 1e18
		for shift := 0; shift < 26; shift++ {
			var counts [26]int
			n := 0
			for i := col; i < len(letters); i += bestLen {
				c := (int(letters[i]-'A') - shift + 26) % 26
				counts[c]++
				n++
			}
			if n == 0 {
				continue
			}
			var chi float64
			for i := 0; i < 26; i++ {
				exp := englishFreq[i] / 100 * float64(n)
				obs := float64(counts[i])
				if exp > 0 {
					chi += (obs - exp) * (obs - exp) / exp
				}
			}
			if chi < bestChi {
				bestChi = chi
				bestShift = shift
			}
		}
		key[col] = byte('A' + bestShift)
	}
	// Produce plaintext
	plain := make([]byte, len(letters))
	for i, c := range letters {
		shift := int(key[i%bestLen] - 'A')
		plain[i] = byte('A' + (int(c-'A')-shift+26)%26)
	}
	r.AddExtra("key_length", bestLen)
	r.AddExtra("key", string(key))
	r.AddExtra("ioc", bestIOC)
	preview := string(plain)
	if len(preview) > 200 {
		preview = preview[:200]
	}
	r.AddExtra("plaintext_preview", preview)
	r.Add(core.Finding{Tool: "cryptan", Severity: core.SevHigh,
		Title:  fmt.Sprintf("Vigenere key %q (len=%d)", string(key), bestLen),
		Detail: preview})
	r.Finish()
	return r
}

// RSAWeak checks small factors and trivial weakness heuristics.
func RSAWeak(nStr, eStr string) *core.Result {
	r := core.NewResult("cryptan-rsa", nStr)
	nStr = strings.TrimPrefix(strings.ToLower(nStr), "0x")
	// Try decimal then hex
	var n uint64
	fmt.Sscanf(nStr, "%d", &n)
	if n == 0 {
		fmt.Sscanf(nStr, "%x", &n)
	}
	if n < 4 {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevMed, Title: "modulus too small or unparsed"})
		r.Finish()
		return r
	}
	r.AddExtra("n", n)
	r.AddExtra("e", eStr)
	// Trial division up to 1e6 or sqrt
	limit := uint64(1_000_000)
	if n < limit*limit {
		limit = 0
		for i := uint64(2); i*i <= n; i++ {
			if n%i == 0 {
				r.Add(core.Finding{Tool: "cryptan", Severity: core.SevCrit,
					Title: "RSA factored", Detail: fmt.Sprintf("p=%d q=%d", i, n/i),
					Evidence: map[string]any{"p": i, "q": n / i}})
				r.Finish()
				return r
			}
		}
	} else {
		for i := uint64(2); i <= limit; i++ {
			if n%i == 0 {
				r.Add(core.Finding{Tool: "cryptan", Severity: core.SevCrit,
					Title: "RSA has small factor", Detail: fmt.Sprintf("factor=%d", i),
					Evidence: map[string]any{"factor": i}})
				r.Finish()
				return r
			}
		}
	}
	r.Add(core.Finding{Tool: "cryptan", Severity: core.SevInfo,
		Title: "no small factors found (within search limit)"})
	r.Finish()
	return r
}

// DetectECB looks for repeated 16-byte blocks.
func DetectECB(data []byte) *core.Result {
	r := core.NewResult("cryptan-ecb", "")
	const bs = 16
	if len(data) < bs*2 {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevMed, Title: "too short for ECB detection"})
		r.Finish()
		return r
	}
	seen := map[string]int{}
	dups := 0
	for i := 0; i+bs <= len(data); i += bs {
		block := string(data[i : i+bs])
		seen[block]++
		if seen[block] == 2 {
			dups++
		}
	}
	r.AddExtra("blocks", len(data)/bs)
	r.AddExtra("duplicate_blocks", dups)
	if dups > 0 {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevHigh,
			Title:  fmt.Sprintf("ECB mode likely (%d repeated blocks)", dups),
			Detail: "identical ciphertext blocks indicate ECB"})
	} else {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevInfo, Title: "no repeated blocks (not ECB or insufficient data)"})
	}
	r.Finish()
	return r
}
