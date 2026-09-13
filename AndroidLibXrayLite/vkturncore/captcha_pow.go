package vkturncore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

const powResultGlobal = "captchaPowResult"

var (
	rePowArgs   = regexp.MustCompile(`\}\(\s*["']([A-Za-z0-9_-]{8,})["']\s*,\s*(\d+)\s*,\s*["'][^"']*["']\s*\)\s*\)`)
	rePowPrefix = regexp.MustCompile(powResultGlobal + `["'\]]{0,3}\s*=\s*["']([A-Za-z0-9._-]{0,8})["']\s*\+`)
)

type powParams struct {
	Input      string
	Difficulty int
	Prefix     string
}

type powResult struct {
	Hash       string          `json:"hash"`
	Nonce      int             `json:"nonce"`
	DurationMs int64           `json:"duration_ms"`
	Telemetry  json.RawMessage `json:"telemetry"`
	TelHash    string          `json:"tel_hash"`
}

func parsePowParams(html string) (powParams, error) {
	m := rePowArgs.FindStringSubmatch(html)
	if len(m) < 3 {
		return powParams{}, errors.New("captcha pow args not found")
	}
	difficulty, err := strconv.Atoi(m[2])
	if err != nil || difficulty <= 0 {
		return powParams{}, fmt.Errorf("invalid captcha difficulty %q", m[2])
	}
	prefix := rePowPrefix.FindStringSubmatch(html)
	if len(prefix) < 2 {
		return powParams{}, errors.New("captcha pow envelope not recognized")
	}
	return powParams{Input: m[1], Difficulty: difficulty, Prefix: prefix[1]}, nil
}

func (s *captchaSession) powEnvelope(p powParams) (string, error) {
	hash, nonce := solvePoW(s.ctx, p.Input, p.Difficulty)
	if hash == "" {
		return "", errors.New("captcha pow failed")
	}
	telemetry, err := marshalJS(s.powTelemetry())
	if err != nil {
		return "", fmt.Errorf("captcha pow telemetry: %w", err)
	}
	telHash, err := telemetryHash(telemetry)
	if err != nil {
		return "", fmt.Errorf("captcha pow tel_hash: %w", err)
	}
	envelope, err := marshalJS(powResult{
		Hash:       hash,
		Nonce:      nonce,
		DurationMs: powDurationMs(nonce),
		Telemetry:  telemetry,
		TelHash:    telHash,
	})
	if err != nil {
		return "", fmt.Errorf("captcha pow encode: %w", err)
	}
	return p.Prefix + base64.StdEncoding.EncodeToString(envelope), nil
}

func solvePoW(ctx context.Context, input string, difficulty int) (string, int) {
	if input == "" || difficulty <= 0 {
		return "", 0
	}
	target := strings.Repeat("0", difficulty)
	buf := make([]byte, 0, len(input)+20)
	buf = append(buf, input...)
	for nonce := 0; nonce <= 10_000_000; nonce++ {
		if nonce&1023 == 0 {
			select {
			case <-ctx.Done():
				return "", 0
			default:
			}
		}
		buf = strconv.AppendInt(buf[:len(input)], int64(nonce), 10)
		sum := sha256.Sum256(buf)
		hashHex := hex.EncodeToString(sum[:])
		if strings.HasPrefix(hashHex, target) {
			return hashHex, nonce
		}
	}
	return "", 0
}

func powDurationMs(nonce int) int64 {
	return max(1, int64(math.Round(float64(nonce+1)*0.015)))
}

func telemetryHash(telemetry []byte) (string, error) {
	var v any
	if err := json.Unmarshal(telemetry, &v); err != nil {
		return "", err
	}
	canonical, err := marshalJS(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func marshalJS(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

type powTelemetryData struct {
	Globals          powProbe `json:"globals"`
	UA               powProbe `json:"ua"`
	Frame            powProbe `json:"frame"`
	MatchMedia       powProbe `json:"match_media"`
	Plugins          powProbe `json:"plugins"`
	NavTamper        powProbe `json:"nav_tamper"`
	Referrer         powProbe `json:"referrer"`
	DevTools         powProbe `json:"devtools"`
	CSS              powProbe `json:"css"`
	NativeIntegrity  powProbe `json:"native_integrity"`
	CookieTest       powProbe `json:"cookie_test"`
	AncestorOrigins  powProbe `json:"ancestor_origins"`
	SandboxBehavior  powProbe `json:"sandbox_behavior"`
	MaxTouchPoints   powProbe `json:"max_touch_points"`
	TimezoneLocale   powProbe `json:"timezone_locale"`
	DevicePixelRatio powProbe `json:"device_pixel_ratio"`
}

type powProbe struct {
	OK     bool `json:"ok"`
	Result any  `json:"result"`
}

func probe(result any) powProbe { return powProbe{OK: true, Result: result} }

type powGlobals struct {
	Doc          bool `json:"doc"`
	Win          bool `json:"win"`
	Nav          bool `json:"nav"`
	Webdriver    bool `json:"webdriver"`
	Subtle       bool `json:"subtle"`
	Secure       bool `json:"secure"`
	GCS          bool `json:"gcs"`
	RAF          bool `json:"raf"`
	Wasm         bool `json:"wasm"`
	PluginsLen   int  `json:"plugins_len"`
	LanguagesLen int  `json:"languages_len"`
	HW           int  `json:"hw"`
	Mem          *int `json:"mem"`
}

type powUA struct {
	UserAgent     string     `json:"userAgent"`
	UserAgentData *powUAData `json:"userAgentData"`
}

type powUAData struct {
	Brands       []CaptchaBrand `json:"brands"`
	Platform     string         `json:"platform"`
	Mobile       bool           `json:"mobile"`
	Architecture *string        `json:"architecture"`
}

type powFrame struct {
	FrameElement       *string `json:"frameElement"`
	AncestorOriginsLen int     `json:"ancestorOriginsLen"`
	ParentAccessible   bool    `json:"parentAccessible"`
}

type powMatchMedia struct {
	PrefersDark   bool `json:"prefersDark"`
	PrefersLight  bool `json:"prefersLight"`
	ReducedMotion bool `json:"reducedMotion"`
	PointerFine   bool `json:"pointerFine"`
}

type powPlugins struct {
	Length       int        `json:"length"`
	Names        []string   `json:"names"`
	Descriptions []string   `json:"descriptions"`
	MimeTypes    [][]string `json:"mimeTypes"`
	IsChrome     bool       `json:"isChrome"`
}

type powNavTamper struct {
	Tampered       bool   `json:"tampered"`
	ElCtor         string `json:"el_ctor"`
	StyleCtor      string `json:"style_ctor"`
	NavCtor        string `json:"nav_ctor"`
	AlertNative    bool   `json:"alert_native"`
	ToStringNative bool   `json:"to_string_native"`
}

type powReferrer struct {
	Referrer string `json:"referrer"`
	InIframe bool   `json:"inIframe"`
	Domain   string `json:"domain"`
}

func (s *captchaSession) powTelemetry() powTelemetryData {
	p := s.profile
	var mem *int
	if m := p.DeviceMemory(); m != nil {
		mem = m
	}
	pluginsList := defaultPlugins(p.IsMobile())
	return powTelemetryData{
		Globals: probe(powGlobals{
			Doc:          true,
			Win:          true,
			Nav:          true,
			Webdriver:    p.Webdriver(),
			Subtle:       true,
			Secure:       true,
			GCS:          true,
			RAF:          true,
			Wasm:         true,
			PluginsLen:   len(pluginsList),
			LanguagesLen: len(p.Languages()),
			HW:           p.HardwareConcurrency(),
			Mem:          mem,
		}),
		UA: probe(powUA{
			UserAgent: p.UserAgent,
			UserAgentData: &powUAData{
				Brands:       p.Brands(),
				Platform:     p.PlatformName(),
				Mobile:       p.IsMobile(),
				Architecture: nil,
			},
		}),
		Frame: probe(powFrame{
			FrameElement:       nil,
			AncestorOriginsLen: 0,
			ParentAccessible:   true,
		}),
		MatchMedia: probe(powMatchMedia{
			PrefersDark:   false,
			PrefersLight:  true,
			ReducedMotion: false,
			PointerFine:   !p.IsMobile(),
		}),
		Plugins: probe(powPlugins{
			Length:       len(pluginsList),
			Names:        pluginsList,
			Descriptions: pluginsDescriptions(pluginsList),
			MimeTypes:    pluginsMimeTypes(pluginsList),
			IsChrome:     true,
		}),
		NavTamper: probe(powNavTamper{
			Tampered:       false,
			ElCtor:         "[object HTMLDivElementConstructor]",
			StyleCtor:      "[object CSSStyleDeclarationConstructor]",
			NavCtor:        "[object NavigatorConstructor]",
			AlertNative:    true,
			ToStringNative: true,
		}),
		Referrer: probe(powReferrer{
			Referrer: "",
			InIframe: false,
			Domain:   s.domain,
		}),
		DevTools:         probe(false),
		CSS:              probe(true),
		NativeIntegrity:  probe(true),
		CookieTest:       probe(true),
		AncestorOrigins:  probe([]string{}),
		SandboxBehavior:  probe(false),
		MaxTouchPoints:   probe(p.MaxTouchPoints()),
		TimezoneLocale:   probe([]string{p.Timezone(), "ru-RU"}),
		DevicePixelRatio: probe(p.DevicePixelRatio()),
	}
}

func defaultPlugins(mobile bool) []string {
	if mobile {
		return []string{}
	}
	return []string{
		"PDF Viewer",
		"Chrome PDF Viewer",
		"Chromium PDF Viewer",
		"Microsoft Edge PDF Viewer",
		"WebKit built-in PDF",
	}
}

func pluginsDescriptions(names []string) []string {
	out := make([]string, len(names))
	for i := range names {
		out[i] = "Portable Document Format"
	}
	return out
}

func pluginsMimeTypes(names []string) [][]string {
	out := make([][]string, len(names))
	for i := range names {
		out[i] = []string{"application/pdf", "text/pdf"}
	}
	return out
}
