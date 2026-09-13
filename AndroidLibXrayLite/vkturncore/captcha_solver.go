package vkturncore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	neturl "net/url"
	"regexp"
	"strings"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
)

const (
	captchaAPIVersion = "5.131"
	captchaAPIOrigin  = "https://id.vk.ru"
	captchaAPIHost    = "api.vk.ru"
	captchaDomain     = "vk.ru"
)

var (
	reCaptchaInitGlobal = regexp.MustCompile(`window\.init\s*=\s*\{`)
	reCaptchaVKGlobal   = regexp.MustCompile(`window\.vk\s*=\s*\{`)
	reCaptchaDebugInfo  = regexp.MustCompile(`[A-Za-z_$][\w$]*:\s*"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"`)

	errCaptchaRateLimit = errors.New("captcha session rate limit reached")
	errCaptchaBot       = errors.New("captcha bot challenge")
	errUnavailable      = errors.New("captcha unavailable")

	captchaMaxAttempts = 2
)

type captchaInitSetting struct {
	Type        string `json:"type"`
	Settings    string `json:"settings"`
	SettingsKey string `json:"settings_key"`
}

type captchaContentRef struct {
	Source string
	Value  string
}

func (s captchaInitSetting) contentRef() captchaContentRef {
	if v := strings.TrimSpace(s.SettingsKey); v != "" {
		return captchaContentRef{Source: "settings_key", Value: v}
	}
	if v := strings.TrimSpace(s.Settings); v != "" {
		return captchaContentRef{Source: "captcha_settings", Value: v}
	}
	return captchaContentRef{}
}

type captchaInitData struct {
	Found    bool
	APIHost  string
	ShowType string
	Content  captchaContentRef
}

type captchaPage struct {
	Pow       powParams
	DebugInfo string
	Init      captchaInitData
}

type captchaCheck struct {
	Status       string
	SuccessToken string
	ShowType     string
	Content      captchaContentRef
}

type captchaShowTypeError struct {
	ShowType string
	Content  captchaContentRef
}

func (e *captchaShowTypeError) Error() string {
	return "captcha show type mismatch: " + e.ShowType
}

type captchaSession struct {
	ctx          context.Context
	client       tlsclient.HttpClient
	profile      CaptchaBrowserProfile
	domain       string
	apiHost      string
	pageURL      string
	pageOrigin   string
	checked      bool
	browserFP    string
	debugInfo    string
	powHash      string
	downlink     float64
	sensors      sensorConfig
	sensorsStart time.Time
	started      time.Time
}

// SolveCaptcha solves VK Smart Captcha automatically using the FreeTurn engine.
func SolveCaptcha(
	ctx context.Context,
	captchaErr *CaptchaError,
	streamID int,
	client tlsclient.HttpClient,
	profile CaptchaBrowserProfile,
) (string, error) {
	if captchaErr == nil || captchaErr.SessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri")
	}
	log.Printf("[STREAM %d] [Captcha] Solving VK Smart Captcha automatically (platform=%s)...", streamID, profile.Platform)

	s := &captchaSession{
		ctx:       ctx,
		client:    client,
		profile:   profile,
		domain:    captchaDomain,
		apiHost:   captchaAPIHost,
		browserFP: profile.VisitorID,
		downlink:  sessionDownlink(),
		sensors:   defaultSensorConfig(),
		started:   time.Now(),
	}

	var solveErr error
	for attempt := 1; attempt <= captchaMaxAttempts; attempt++ {
		var token string
		token, solveErr = s.solveOnce(captchaErr)
		if solveErr == nil {
			log.Printf("[STREAM %d] [Captcha] solver succeeded", streamID)
			return token, nil
		}
		log.Printf("[STREAM %d] [Captcha] solve attempt %d failed: %v", streamID, attempt, solveErr)
		if s.checked || errors.Is(solveErr, errCaptchaRateLimit) || errors.Is(solveErr, errCaptchaBot) {
			return "", solveErr
		}

		backoffSteps := min(attempt, 10)
		timer := time.NewTimer(time.Duration(backoffSteps) * 500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
	}
	return "", fmt.Errorf("captcha attempts exhausted: %w", solveErr)
}

func (s *captchaSession) solveOnce(captchaErr *CaptchaError) (string, error) {
	s.domain = captchaDomainFromRedirectURI(captchaErr.RedirectURI)
	s.setPageURL(captchaErr.RedirectURI)

	html, err := s.fetchCaptchaHTML(captchaErr.RedirectURI)
	if err != nil {
		return "", err
	}

	page, err := parseCaptchaPage(html)
	if err != nil {
		return "", err
	}

	assets := parsePageAssets(html)
	assetsDone := make(chan struct{})
	go func() {
		defer close(assetsDone)
		s.loadAssets(assets)
	}()
	defer func() { <-assetsDone }()

	s.powHash, err = s.powEnvelope(page.Pow)
	if err != nil {
		return "", err
	}

	s.debugInfo = page.DebugInfo
	<-assetsDone

	if page.Init.APIHost != "" {
		s.apiHost = page.Init.APIHost
	}

	var showType string
	var sliderContent captchaContentRef
	if page.Init.Found {
		showType, sliderContent = page.Init.ShowType, page.Init.Content
	} else {
		initResp, initErr := s.captchaRequest("captchaNotRobot.initSession", [][2]string{
			{"session_token", captchaErr.SessionToken},
			{"domain", s.domain},
			{"lang", "0"},
		})
		if initErr != nil {
			return "", fmt.Errorf("captcha initSession failed: %w", initErr)
		}
		showType, sliderContent = parseCaptchaInitSession(initResp)
	}

	base := s.captchaBaseValues(captchaErr.SessionToken)
	settingsResp, err := s.captchaRequest("captchaNotRobot.settings", base)
	if err != nil {
		return "", fmt.Errorf("captcha settings failed: %w", err)
	}
	s.sensors = parseSensorConfig(settingsResp)
	s.sensorsStart = time.Now()

	if dwellErr := s.dwell(250, 400); dwellErr != nil {
		return "", dwellErr
	}

	var token string
	switch showType {
	case "slider":
		token, err = s.solveSliderCaptcha(captchaErr.SessionToken, sliderContent)
	case "checkbox", "":
		token, err = s.solveCheckboxCaptcha(captchaErr.SessionToken)
	default:
		return "", fmt.Errorf("unsupported captcha type: %s", showType)
	}
	if err != nil {
		token, err = s.escalate(captchaErr.SessionToken, sliderContent, err)
	}
	if err != nil {
		_, _ = s.captchaRequest("captchaNotRobot.leaveCaptcha", base)
		return "", err
	}

	_, _ = s.captchaRequest("captchaNotRobot.endSession", base)
	return token, nil
}

func (s *captchaSession) solveCheckboxCaptcha(sessionToken string) (string, error) {
	if err := s.sendComponentDone(sessionToken); err != nil {
		return "", err
	}
	if err := s.clickReaction(); err != nil {
		return "", err
	}
	check, err := s.performCaptchaCheck(sessionToken, "{}")
	if err != nil {
		return "", err
	}
	if strings.EqualFold(check.Status, "ok") {
		if check.SuccessToken == "" {
			return "", errors.New("captcha success token not found")
		}
		return check.SuccessToken, nil
	}
	if strings.EqualFold(check.Status, "error_limit") {
		return "", errCaptchaRateLimit
	}
	if check.ShowType != "" && !strings.EqualFold(check.ShowType, "checkbox") {
		return "", &captchaShowTypeError{ShowType: check.ShowType, Content: check.Content}
	}
	return "", fmt.Errorf("captcha checkbox status: %s", check.Status)
}

func (s *captchaSession) sendComponentDone(sessionToken string) error {
	values := s.captchaBaseValues(sessionToken)
	values = append(values,
		[2]string{"browser_fp", s.browserFP},
		[2]string{"device", s.profile.DeviceJSON},
	)
	resp, err := s.captchaRequest("captchaNotRobot.componentDone", values)
	if err != nil {
		return fmt.Errorf("captcha componentDone failed: %w", err)
	}
	if respObj, ok := resp["response"].(map[string]any); ok {
		if status := captchaStringifyAny(respObj["status"]); status != "" && !strings.EqualFold(status, "ok") {
			return fmt.Errorf("componentDone status: %s", status)
		}
	}
	return nil
}

func (s *captchaSession) escalate(sessionToken string, initContent captchaContentRef, cause error) (string, error) {
	var mismatch *captchaShowTypeError
	if !errors.As(cause, &mismatch) || !strings.EqualFold(mismatch.ShowType, "slider") {
		return "", cause
	}
	content := mismatch.Content
	if content.Value == "" {
		content = initContent
	}
	if content.Value == "" {
		return "", cause
	}
	if err := s.dwell(500, 1100); err != nil {
		return "", err
	}
	return s.solveSliderCaptcha(sessionToken, content)
}

func (s *captchaSession) clickReaction() error {
	ms := 450 + randIntN(500)
	if randIntN(4) == 0 {
		ms += 700 + randIntN(1800)
	}
	return s.sleepFor(time.Duration(ms) * time.Millisecond)
}

func (s *captchaSession) dwell(minMs, maxMs int) error {
	diff := max(maxMs-minMs, 1)
	return s.sleepFor(time.Duration(minMs+randIntN(diff)) * time.Millisecond)
}

func (s *captchaSession) sleepFor(d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (s *captchaSession) captchaBaseValues(sessionToken string) [][2]string {
	return [][2]string{
		{"session_token", sessionToken},
		{"domain", s.domain},
		{"adFp", ""},
		{"access_token", ""},
	}
}

func captchaDomainFromRedirectURI(redirectURI string) string {
	u, err := neturl.Parse(redirectURI)
	if err != nil || u.Host == "" {
		return captchaDomain
	}
	parts := strings.Split(u.Hostname(), ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return u.Hostname()
}

func parseCaptchaInitSession(raw map[string]any) (string, captchaContentRef) {
	resp, ok := raw["response"].(map[string]any)
	if !ok {
		return "", captchaContentRef{}
	}
	return captchaStringifyAny(resp["show_captcha_type"]), parseSliderContentRef(resp["content_settings"])
}

func parseSliderContentRef(raw any) captchaContentRef {
	content := captchaContentRef{}
	data, err := json.Marshal(raw)
	if err != nil {
		return content
	}
	var settings []captchaInitSetting
	if json.Unmarshal(data, &settings) != nil {
		return content
	}
	for _, setting := range settings {
		if setting.Type == "slider" {
			content = setting.contentRef()
		}
	}
	return content
}

func parseCaptchaPage(html string) (*captchaPage, error) {
	if !reCaptchaVKGlobal.MatchString(html) && !reCaptchaInitGlobal.MatchString(html) {
		return nil, fmt.Errorf("%w: not a captcha page (bytes=%d)", errUnavailable, len(html))
	}
	pow, err := parsePowParams(html)
	if err != nil {
		return nil, err
	}
	debugInfo := parseCaptchaDebugInfo(html)
	if debugInfo == "" {
		return nil, errors.New("captcha debug_info not found on page")
	}
	return &captchaPage{Pow: pow, DebugInfo: debugInfo, Init: parseCaptchaInitGlobal(html)}, nil
}

func parseCaptchaDebugInfo(html string) string {
	m := reCaptchaVKGlobal.FindStringIndex(html)
	if m == nil {
		return ""
	}
	block := balancedJSONObject(html[m[1]-1:])
	if block == "" {
		return ""
	}
	found := reCaptchaDebugInfo.FindAllStringSubmatch(block, -1)
	if len(found) == 0 {
		return ""
	}
	return found[0][1]
}

func parseCaptchaInitGlobal(html string) captchaInitData {
	m := reCaptchaInitGlobal.FindStringIndex(html)
	if m == nil {
		return captchaInitData{}
	}
	raw := balancedJSONObject(html[m[1]-1:])
	if raw == "" {
		return captchaInitData{}
	}
	var parsed struct {
		Hosts struct {
			API string `json:"api"`
		} `json:"hosts"`
		Data struct {
			ShowCaptchaType string               `json:"show_captcha_type"`
			CaptchaSettings []captchaInitSetting `json:"captcha_settings"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(raw), &parsed) != nil {
		return captchaInitData{}
	}
	content := captchaContentRef{}
	for _, s := range parsed.Data.CaptchaSettings {
		if s.Type == "slider" {
			content = s.contentRef()
		}
	}
	return captchaInitData{
		Found:    true,
		APIHost:  parsed.Hosts.API,
		ShowType: parsed.Data.ShowCaptchaType,
		Content:  content,
	}
}

func balancedJSONObject(s string) string {
	depth := 0
	inStr := false
	esc := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inStr && esc:
			esc = false
		case inStr && c == '\\':
			esc = true
		case inStr && c == '"':
			inStr = false
		case inStr:
		case c == '"':
			inStr = true
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return s[:i+1]
			}
		}
	}
	return ""
}

func (s *captchaSession) setPageURL(raw string) {
	s.pageURL = captchaAPIOrigin + "/"
	s.pageOrigin = captchaAPIOrigin
	u, err := neturl.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return
	}
	s.pageURL = raw
	s.pageOrigin = u.Scheme + "://" + u.Host
}

func (s *captchaSession) pageIsAPIOrigin() bool {
	return s.pageOrigin == "https://"+s.apiHost
}

func (s *captchaSession) apiRequestHeaders() map[string]string {
	if s.pageIsAPIOrigin() {
		return map[string]string{
			"Origin":         s.pageOrigin,
			"Referer":        s.pageURL,
			"Sec-Fetch-Site": "same-origin",
		}
	}
	return map[string]string{
		"Origin":         s.pageOrigin,
		"Referer":        s.pageOrigin + "/",
		"Sec-Fetch-Site": "same-site",
	}
}

func (s *captchaSession) captchaRequest(method string, form [][2]string) (map[string]any, error) {
	endpoint := "https://" + s.apiHost + "/method/" + method + "?v=" + captchaAPIVersion
	body, err := s.doRaw(fhttp.MethodPost, endpoint, form, s.apiRequestHeaders())
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("captcha api decode: %w", err)
	}
	return out, nil
}

func (s *captchaSession) performCaptchaCheck(
	sessionToken string,
	answerJSON string,
) (*captchaCheck, error) {
	s.checked = true
	sinceSettings := time.Since(s.sensorsStart)
	data := buildAnalytics(s.sensors, s.downlink, sinceSettings)
	values := make([][2]string, 0, 15)
	values = append(values,
		[2]string{"session_token", sessionToken},
		[2]string{"domain", s.domain},
		[2]string{"adFp", ""},
	)
	values = append(values, data.fields()...)
	values = append(values,
		[2]string{"browser_fp", s.browserFP},
		[2]string{"hash", s.powHash},
		[2]string{"answer", base64.StdEncoding.EncodeToString([]byte(answerJSON))},
		[2]string{"debug_info", s.debugInfo},
		[2]string{"access_token", ""},
	)
	resp, err := s.captchaRequest("captchaNotRobot.check", values)
	if err != nil {
		return nil, fmt.Errorf("captcha check failed: %w", err)
	}
	return parseCaptchaCheck(resp)
}

func parseCaptchaCheck(raw map[string]any) (*captchaCheck, error) {
	resp, ok := raw["response"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid captcha check response: %v", raw)
	}
	out := &captchaCheck{
		Status:       captchaStringifyAny(resp["status"]),
		SuccessToken: captchaStringifyAny(resp["success_token"]),
		ShowType:     captchaStringifyAny(resp["show_captcha_type"]),
		Content:      parseSliderContentRef(resp["content_settings"]),
	}
	if out.Status == "" {
		return nil, fmt.Errorf("missing status in captcha check: %v", raw)
	}
	return out, nil
}

func (s *captchaSession) fetchCaptchaHTML(redirectURI string) (string, error) {
	headers := map[string]string{
		"Sec-Fetch-Site": "none",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-Dest": "document",
		"Sec-Fetch-User": "?1",
		"Accept":         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
	}
	body, err := s.doRaw(fhttp.MethodGet, redirectURI, nil, headers)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (s *captchaSession) doRaw(
	method, url string,
	form [][2]string,
	headers map[string]string,
) ([]byte, error) {
	var bodyReader io.Reader
	if len(form) > 0 {
		values := neturl.Values{}
		for _, pair := range form {
			values.Add(pair[0], pair[1])
		}
		bodyReader = strings.NewReader(values.Encode())
	}
	req, err := fhttp.NewRequestWithContext(s.ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	ApplyBrowserProfileToFhttp(req, s.profile)
	if len(form) > 0 {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func captchaStringifyAny(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		return fmt.Sprintf("%.0f", val)
	case int:
		return fmt.Sprintf("%d", val)
	default:
		return ""
	}
}
