package vkturncore

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	neturl "net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
)

type VkCaptchaError struct {
	ErrorCode               int
	ErrorMsg                string
	CaptchaSid              string
	CaptchaImg              string
	RedirectURI             string
	IsSoundCaptchaAvailable bool
	SessionToken            string
	CaptchaTs               string
	CaptchaAttempt          string
}

func (e *VkCaptchaError) IsCaptchaError() bool {
	return e.ErrorCode == 14 && e.RedirectURI != "" && e.SessionToken != ""
}

func ParseVkCaptchaError(errData map[string]interface{}) *VkCaptchaError {
	codeFloat, ok := errData["error_code"].(float64)
	if !ok {
		return nil
	}
	code := int(codeFloat)

	RedirectURI, ok := errData["redirect_uri"].(string)
	if !ok {
		return nil
	}

	var captchaSid string
	if sidStr, ok2 := errData["captcha_sid"].(string); ok2 {
		captchaSid = sidStr
	} else if sidNum, ok2 := errData["captcha_sid"].(float64); ok2 {
		captchaSid = fmt.Sprintf("%.0f", sidNum)
	}

	captchaImg, _ := errData["captcha_img"].(string)
	errorMsg, _ := errData["error_msg"].(string)

	var sessionToken string
	if RedirectURI != "" {
		if parsed, err := neturl.Parse(RedirectURI); err == nil {
			sessionToken = parsed.Query().Get("session_token")
		}
	}

	isSound, _ := errData["is_sound_captcha_available"].(bool)

	var captchaTs string
	if tsFloat, ok := errData["captcha_ts"].(float64); ok {
		captchaTs = fmt.Sprintf("%.0f", tsFloat)
	} else if tsStr, ok := errData["captcha_ts"].(string); ok {
		captchaTs = tsStr
	}

	var captchaAttempt string
	if attFloat, ok := errData["captcha_attempt"].(float64); ok {
		captchaAttempt = fmt.Sprintf("%.0f", attFloat)
	} else if attStr, ok := errData["captcha_attempt"].(string); ok {
		captchaAttempt = attStr
	}

	return &VkCaptchaError{
		ErrorCode:               code,
		ErrorMsg:                errorMsg,
		CaptchaSid:              captchaSid,
		CaptchaImg:              captchaImg,
		RedirectURI:             RedirectURI,
		IsSoundCaptchaAvailable: isSound,
		SessionToken:            sessionToken,
		CaptchaTs:               captchaTs,
		CaptchaAttempt:          captchaAttempt,
	}
}

func generateBrowserFp(profile Profile) string {
	data := profile.UserAgent + profile.SecChUa + "1920x1080x24" + strconv.FormatInt(time.Now().UnixNano(), 10)
	h := md5.Sum([]byte(data))
	return hex.EncodeToString(h[:])
}

func generateFakeCursor() string {
	startX := 600 + rand.Intn(400)
	startY := 300 + rand.Intn(200)
	startTime := time.Now().UnixMilli() - int64(rand.Intn(2000)+1000)
	var points []string
	for i := 0; i < 15+rand.Intn(10); i++ {
		startX += rand.Intn(15) - 5
		startY += rand.Intn(15) + 2
		startTime += int64(rand.Intn(40) + 10)
		points = append(points, fmt.Sprintf(`{"x":%d,"y":%d,"t":%d}`, startX, startY, startTime))
	}
	return "[" + strings.Join(points, ",") + "]"
}

func applyBrowserProfileFhttp(req *fhttp.Request, profile Profile) {
	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("sec-ch-ua", profile.SecChUa)
	req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,ru;q=0.8")
	req.Header.Set("DNT", "1")
}

func buildCaptchaDeviceJSON(profile Profile) string {
	return fmt.Sprintf(
		`{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1040,"innerWidth":1920,"innerHeight":969,"devicePixelRatio":1,"language":"en-US","languages":["en-US","ru-RU"],"webdriver":false,"hardwareConcurrency":8,"deviceMemory":8,"connectionEffectiveType":"4g","notificationsPermission":"default","userAgent":"%s","platform":"Win32"}`,
		profile.UserAgent,
	)
}

func solvePoW(powInput string, difficulty int) string {
	target := strings.Repeat("0", difficulty)
	for nonce := 1; nonce <= 10000000; nonce++ {
		data := powInput + strconv.Itoa(nonce)
		hash := sha256.Sum256([]byte(data))
		hexHash := hex.EncodeToString(hash[:])
		if strings.HasPrefix(hexHash, target) {
			return hexHash
		}
	}
	return ""
}

type captchaBootstrap struct {
	PowInput   string
	Difficulty int
	Settings   *captchaSettingsResponse
}

func fetchCaptchaBootstrap(ctx context.Context, redirectURI string, client tlsclient.HttpClient, profile Profile) (*captchaBootstrap, error) {
	parsedURL, err := neturl.Parse(redirectURI)
	if err != nil {
		return nil, err
	}
	domain := parsedURL.Hostname()

	req, err := fhttp.NewRequestWithContext(ctx, "GET", redirectURI, nil)
	if err != nil {
		return nil, err
	}

	req.Host = domain
	applyBrowserProfileFhttp(req, profile)
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	html := string(body)

	settings, _ := parseCaptchaSettingsFromHTML(html)

	// The PoW parameters are now obfuscated at the end of the script: }("seed", difficulty, "error_string"));
	powInputRe := regexp.MustCompile(`\}\(["']([^"']+)["']\s*,\s*(\d+)\s*,\s*["'][^"']+["']\)\);`)
	powInputMatch := powInputRe.FindStringSubmatch(html)
	if len(powInputMatch) >= 3 {
		diff, _ := strconv.Atoi(powInputMatch[2])
		return &captchaBootstrap{
			PowInput:   powInputMatch[1],
			Difficulty: diff,
			Settings:   settings,
		}, nil
	}

	// Fallback to older format if the obfuscation changes back
	oldPowInputRe := regexp.MustCompile(`powInput\s*=\s*['"]([^'"]+)['"]`)
	oldPowInputMatch := oldPowInputRe.FindStringSubmatch(html)
	if len(oldPowInputMatch) < 2 {
		return nil, fmt.Errorf("powInput not found in captcha HTML")
	}

	difficulty := 2
	for _, expr := range []*regexp.Regexp{
		regexp.MustCompile(`startsWith\('0'\.repeat\((\d+)\)\)`),
		regexp.MustCompile(`difficulty\s*=\s*(\d+)`),
	} {
		if match := expr.FindStringSubmatch(html); len(match) >= 2 {
			if parsed, err := strconv.Atoi(match[1]); err == nil {
				difficulty = parsed
				break
			}
		}
	}

	return &captchaBootstrap{
		PowInput:   oldPowInputMatch[1],
		Difficulty: difficulty,
		Settings:   settings,
	}, nil
}

func solveVkCaptcha(ctx context.Context, captchaErr *VkCaptchaError, streamID int, client tlsclient.HttpClient, profile Profile) (string, error) {
	log.Printf("[STREAM %d] [VK Captcha] Solving VK Smart Captcha automatically...", streamID)

	if captchaErr.SessionToken == "" || captchaErr.RedirectURI == "" {
		return "", fmt.Errorf("missing captcha session token or redirect uri")
	}

	bootstrap, err := fetchCaptchaBootstrap(ctx, captchaErr.RedirectURI, client, profile)
	if err != nil {
		return "", fmt.Errorf("failed to fetch captcha bootstrap: %w", err)
	}

	hash := solvePoW(bootstrap.PowInput, bootstrap.Difficulty)
	if hash == "" {
		return "", fmt.Errorf("failed to solve PoW within limit")
	}

	// Try slider / automatic solver first (handles both checkbox and slider puzzle)
	successToken, err := callCaptchaNotRobotWithSliderPOC(
		ctx,
		captchaErr.SessionToken,
		hash,
		streamID,
		client,
		profile,
		bootstrap.Settings,
	)
	if err == nil && successToken != "" {
		log.Printf("[STREAM %d] [VK Captcha] solver succeeded", streamID)
		return successToken, nil
	}

	log.Printf("[STREAM %d] [VK Captcha] Slider solver failed: %v. Trying standard fallback...", streamID, err)
	return callCaptchaNotRobot(ctx, captchaErr.SessionToken, hash, streamID, client, profile)
}

func callCaptchaNotRobot(ctx context.Context, sessionToken, hash string, streamID int, client tlsclient.HttpClient, profile Profile) (string, error) {
	vkReq := func(method string, postData string) (map[string]interface{}, error) {
		reqURL := "https://api.vk.ru/method/" + method + "?v=5.131"
		parsedURL, err := neturl.Parse(reqURL)
		if err != nil {
			return nil, fmt.Errorf("parse request URL: %w", err)
		}

		req, err := fhttp.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(postData))
		if err != nil {
			return nil, err
		}

		req.Host = parsedURL.Hostname()
		applyBrowserProfileFhttp(req, profile)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Origin", "https://id.vk.ru")
		req.Header.Set("Referer", "https://id.vk.ru/")
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Priority", "u=1, i")

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer httpResp.Body.Close()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}
		var resp map[string]interface{}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}
		return resp, nil
	}

	baseParams := fmt.Sprintf("session_token=%s&domain=vk.com&adFp=&access_token=", neturl.QueryEscape(sessionToken))

	if _, err := vkReq("captchaNotRobot.settings", baseParams); err != nil {
		return "", fmt.Errorf("captcha settings failed: %w", err)
	}

	time.Sleep(150 * time.Millisecond)

	browserFp := generateBrowserFp(profile)
	deviceJSON := buildCaptchaDeviceJSON(profile)
	componentDoneData := baseParams + fmt.Sprintf("&browser_fp=%s&device=%s", browserFp, neturl.QueryEscape(deviceJSON))

	if _, err := vkReq("captchaNotRobot.componentDone", componentDoneData); err != nil {
		return "", fmt.Errorf("captcha componentDone failed: %w", err)
	}

	time.Sleep(150 * time.Millisecond)

	cursorJSON := generateFakeCursor()
	answer := base64.StdEncoding.EncodeToString([]byte("{}"))
	debugInfoBytes := md5.Sum([]byte(profile.UserAgent + strconv.FormatInt(time.Now().UnixNano(), 10)))
	debugInfo := hex.EncodeToString(debugInfoBytes[:])
	connectionRtt := "[50,50,50,50,50,50,50,50,50,50]"
	connectionDownlink := "[9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5]"

	checkData := baseParams + fmt.Sprintf(
		"&accelerometer=%s&gyroscope=%s&motion=%s&cursor=%s&taps=%s&connectionRtt=%s&connectionDownlink=%s&browser_fp=%s&hash=%s&answer=%s&debug_info=%s",
		neturl.QueryEscape("[]"), neturl.QueryEscape("[]"), neturl.QueryEscape("[]"),
		neturl.QueryEscape(cursorJSON), neturl.QueryEscape("[]"), neturl.QueryEscape(connectionRtt),
		neturl.QueryEscape(connectionDownlink),
		browserFp, hash, answer, debugInfo,
	)

	checkResp, err := vkReq("captchaNotRobot.check", checkData)
	if err != nil {
		return "", fmt.Errorf("captcha check failed: %w", err)
	}

	respObj, ok := checkResp["response"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid captcha check response: %v", checkResp)
	}
	status, _ := respObj["status"].(string)
	if status != "OK" {
		return "", fmt.Errorf("captcha check status: %s", status)
	}
	successToken, _ := respObj["success_token"].(string)
	if successToken == "" {
		return "", fmt.Errorf("success_token missing in captcha response")
	}

	time.Sleep(150 * time.Millisecond)
	_, _ = vkReq("captchaNotRobot.endSession", baseParams)

	return successToken, nil
}

func getCustomNetDialer() net.Dialer {
	return net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				var d net.Dialer
				dnsServers := []string{"77.88.8.8:53", "8.8.8.8:53", "1.1.1.1:53"}
				var lastErr error
				for _, dns := range dnsServers {
					conn, err := d.DialContext(ctx, "udp", dns)
					if err == nil {
						return conn, nil
					}
					lastErr = err
				}
				return nil, lastErr
			},
		},
	}
}
