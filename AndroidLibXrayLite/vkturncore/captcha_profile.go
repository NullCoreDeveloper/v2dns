package vkturncore

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/tls-client/profiles"
)

const (
	chromeSecChUa = `"Google Chrome";v="146", "Chromium";v="146", "Not)A;Brand";v="24"`

	uaWindows = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
	uaMac     = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
	uaAndroid = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36"

	timezoneMoscow    = "Europe/Moscow"
	touchPointsMobile = 5
)

type CaptchaPlatform string

const (
	CaptchaPlatformDesktop CaptchaPlatform = "desktop"
	CaptchaPlatformMobile  CaptchaPlatform = "mobile"
)

func CaptchaPlatformFromString(s string) CaptchaPlatform {
	if s == string(CaptchaPlatformMobile) {
		return CaptchaPlatformMobile
	}
	return CaptchaPlatformDesktop
}

type CaptchaBrowserProfile struct {
	Platform        CaptchaPlatform
	UserAgent       string
	SecChUa         string
	SecChUaMobile   string
	SecChUaPlatform string
	AcceptLanguage  string
	DeviceJSON      string
	VisitorID       string

	cores     int
	memGB     int
	webdriver bool
	dev       captchaDevice
}

func (p CaptchaBrowserProfile) IsMobile() bool { return p.Platform == CaptchaPlatformMobile }

func (p CaptchaBrowserProfile) HardwareConcurrency() int { return p.cores }

func (p CaptchaBrowserProfile) Webdriver() bool { return p.webdriver }

func (p CaptchaBrowserProfile) DeviceMemory() *int {
	if p.memGB == 0 {
		return nil
	}
	return &p.memGB
}

func (p CaptchaBrowserProfile) Languages() []string { return p.dev.Languages }

func (p CaptchaBrowserProfile) DevicePixelRatio() float64 { return p.dev.DevicePixelRatio }

func (CaptchaBrowserProfile) Timezone() string { return timezoneMoscow }

func (p CaptchaBrowserProfile) MaxTouchPoints() int {
	if p.IsMobile() {
		return touchPointsMobile
	}
	return 0
}

func (p CaptchaBrowserProfile) Orientation() string {
	if p.IsMobile() {
		return "portrait-primary"
	}
	return "landscape-primary"
}

func (p CaptchaBrowserProfile) PlatformName() string { return strings.Trim(p.SecChUaPlatform, `"`) }

type CaptchaBrand struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

func (p CaptchaBrowserProfile) Brands() []CaptchaBrand {
	out := make([]CaptchaBrand, 0, 3)
	for _, part := range strings.Split(p.SecChUa, ", ") {
		name, ver, ok := strings.Cut(part, ";v=")
		if !ok {
			continue
		}
		out = append(out, CaptchaBrand{Brand: strings.Trim(name, `"`), Version: strings.Trim(ver, `"`)})
	}
	return out
}

type captchaDevice struct {
	ScreenWidth             int      `json:"screenWidth"`
	ScreenHeight            int      `json:"screenHeight"`
	ScreenAvailWidth        int      `json:"screenAvailWidth"`
	ScreenAvailHeight       int      `json:"screenAvailHeight"`
	InnerWidth              int      `json:"innerWidth"`
	InnerHeight             int      `json:"innerHeight"`
	DevicePixelRatio        float64  `json:"devicePixelRatio"`
	Language                string   `json:"language"`
	Languages               []string `json:"languages"`
	Webdriver               bool     `json:"webdriver"`
	HardwareConcurrency     int      `json:"hardwareConcurrency"`
	DeviceMemory            *int     `json:"deviceMemory,omitempty"`
	ConnectionEffectiveType string   `json:"connectionEffectiveType,omitempty"`
	NotificationsPermission string   `json:"notificationsPermission"`
}

var chromeHeaderOrder = []string{
	"content-length",
	"sec-ch-ua-platform",
	"user-agent",
	"sec-ch-ua",
	"content-type",
	"sec-ch-ua-mobile",
	"upgrade-insecure-requests",
	"accept",
	"origin",
	"sec-fetch-site",
	"sec-fetch-mode",
	"sec-fetch-user",
	"sec-fetch-dest",
	"referer",
	"accept-encoding",
	"accept-language",
	"cookie",
	"priority",
}

type captchaDeviceSpec struct {
	userAgent  string
	chPlatform string
	dev        captchaDevice
}

var desktopSpecs = []captchaDeviceSpec{
	{userAgent: uaWindows, chPlatform: `"Windows"`, dev: newCaptchaDevice(1920, 1080, 1032, 1147, 945, 1, 16, 8)},
	{userAgent: uaWindows, chPlatform: `"Windows"`, dev: newCaptchaDevice(1536, 864, 816, 1229, 738, 1.25, 8, 8)},
	{userAgent: uaWindows, chPlatform: `"Windows"`, dev: newCaptchaDevice(2560, 1440, 1392, 1512, 1237, 1, 12, 8)},
	{userAgent: uaMac, chPlatform: `"macOS"`, dev: newCaptchaDevice(1512, 982, 944, 1147, 870, 2, 10, 8)},
}

var mobileSpecs = []captchaDeviceSpec{
	{userAgent: uaAndroid, chPlatform: `"Android"`, dev: newCaptchaDevice(364, 793, 793, 363, 671, 3.5, 8, 8)},
	{userAgent: uaAndroid, chPlatform: `"Android"`, dev: newCaptchaDevice(393, 852, 852, 393, 659, 3, 8, 8)},
	{userAgent: uaAndroid, chPlatform: `"Android"`, dev: newCaptchaDevice(412, 915, 915, 412, 724, 2.625, 8, 4)},
	{userAgent: uaAndroid, chPlatform: `"Android"`, dev: newCaptchaDevice(360, 800, 800, 360, 612, 3, 8, 4)},
	{userAgent: uaAndroid, chPlatform: `"Android"`, dev: newCaptchaDevice(384, 832, 832, 384, 644, 2.75, 8, 8)},
}

type CaptchaIdentity struct {
	Seed string
	Gen  int
}

func (id CaptchaIdentity) String() string { return id.Seed + "|" + strconv.Itoa(id.Gen) }

func ProfileFor(p CaptchaPlatform, id CaptchaIdentity) CaptchaBrowserProfile {
	specs := desktopSpecs
	if p == CaptchaPlatformMobile {
		specs = mobileSpecs
	} else {
		p = CaptchaPlatformDesktop
	}

	sum := sha256.Sum256([]byte(id.String()))
	s := specs[binary.BigEndian.Uint64(sum[:8])%uint64(len(specs))]

	profile := CaptchaBrowserProfile{
		Platform:        p,
		SecChUa:         chromeSecChUa,
		SecChUaMobile:   "?0",
		SecChUaPlatform: s.chPlatform,
		AcceptLanguage:  "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
		UserAgent:       s.userAgent,
	}
	if p == CaptchaPlatformMobile {
		profile.SecChUaMobile = "?1"
	}

	profile = withCaptchaDevice(profile, s.dev)
	profile.VisitorID = computeVisitorID(id, profile)
	return profile
}

func newCaptchaDevice(screenW, screenH, availH, innerW, innerH int, dpr float64, cores, memGB int) captchaDevice {
	memory := memGB
	return captchaDevice{
		ScreenWidth: screenW, ScreenHeight: screenH,
		ScreenAvailWidth: screenW, ScreenAvailHeight: availH,
		InnerWidth: innerW, InnerHeight: innerH,
		DevicePixelRatio:        dpr,
		Language:                "ru-RU",
		Languages:               []string{"ru-RU", "en-US"},
		HardwareConcurrency:     cores,
		DeviceMemory:            &memory,
		ConnectionEffectiveType: "4g",
		NotificationsPermission: "denied",
	}
}

func computeVisitorID(id CaptchaIdentity, p CaptchaBrowserProfile) string {
	sum := sha256.Sum256([]byte(id.String() + "|" + p.UserAgent + "|" + p.DeviceJSON))
	return hex.EncodeToString(sum[:16])
}

func withCaptchaDevice(p CaptchaBrowserProfile, d captchaDevice) CaptchaBrowserProfile {
	data, err := json.Marshal(d)
	if err != nil {
		return p
	}
	p.DeviceJSON = string(data)
	p.dev = d
	p.cores, p.webdriver = d.HardwareConcurrency, d.Webdriver
	if d.DeviceMemory != nil {
		p.memGB = *d.DeviceMemory
	}
	return p
}

func (CaptchaBrowserProfile) ClientProfile() profiles.ClientProfile {
	return profiles.Chrome_146
}

func ApplyBrowserProfileToFhttp(req *fhttp.Request, profile CaptchaBrowserProfile) {
	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("sec-ch-ua", profile.SecChUa)
	req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
	req.Header.Set("Accept-Language", profile.AcceptLanguage)
	if req.Header.Get("Sec-Fetch-Dest") == "document" {
		req.Header.Set("Priority", "u=0, i")
	} else {
		req.Header.Set("Priority", "u=1, i")
	}
	req.Header[fhttp.HeaderOrderKey] = chromeHeaderOrder
}
