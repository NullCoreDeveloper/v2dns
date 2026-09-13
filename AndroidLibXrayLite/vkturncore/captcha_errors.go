package vkturncore

import (
	"fmt"
	neturl "net/url"
)

// CaptchaError describes a VK API captcha required challenge.
type CaptchaError struct {
	ErrorCode               int
	ErrorMsg                string
	CaptchaSid              string
	RedirectURI             string
	IsSoundCaptchaAvailable bool
	SessionToken            string
	CaptchaTs               string
	CaptchaAttempt          string
}

// ParseCaptchaError parses captcha error from VK API response.
func ParseCaptchaError(errData map[string]any) *CaptchaError {
	codeFloat, ok := errData["error_code"].(float64)
	if !ok {
		return nil
	}
	code := int(codeFloat)

	redirectURI, ok := errData["redirect_uri"].(string)
	if !ok {
		return nil
	}

	captchaSid, ok := errData["captcha_sid"].(string)
	if !ok {
		if sidNum, ok2 := errData["captcha_sid"].(float64); ok2 {
			captchaSid = fmt.Sprintf("%.0f", sidNum)
		}
	}

	errorMsg, ok := errData["error_msg"].(string)
	if !ok {
		return nil
	}

	var sessionToken string
	if redirectURI != "" {
		if parsed, err := neturl.Parse(redirectURI); err == nil {
			sessionToken = parsed.Query().Get("session_token")
		} else {
			return nil
		}
	}
	if sessionToken == "" {
		if st, stOk := errData["session_token"].(string); stOk {
			sessionToken = st
		}
	}

	isSound, ok := errData["is_sound_captcha_available"].(bool)
	if !ok {
		isSound = false
	}

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

	return &CaptchaError{
		ErrorCode:               code,
		ErrorMsg:                errorMsg,
		CaptchaSid:              captchaSid,
		RedirectURI:             redirectURI,
		IsSoundCaptchaAvailable: isSound,
		SessionToken:            sessionToken,
		CaptchaTs:               captchaTs,
		CaptchaAttempt:          captchaAttempt,
	}
}

// IsCaptcha returns true if this error is an actionable captcha challenge.
func (e *CaptchaError) IsCaptcha() bool {
	return e != nil && e.ErrorCode == 14 && e.RedirectURI != "" && e.SessionToken != ""
}

// IsCaptchaError is an alias for IsCaptcha for backward compatibility.
func (e *CaptchaError) IsCaptchaError() bool {
	return e.IsCaptcha()
}

