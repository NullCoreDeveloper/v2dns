// ==============================================================================
// VK TURN Proxy Integration for libv2ray
// ==============================================================================

package libv2ray

import (
	"github.com/2dust/AndroidLibXrayLite/vkturncore"
)

// StartVkTurnClient starts the VK TURN client in the background with a base64-encoded JSON config.
func StartVkTurnClient(configJsonBase64 string, logPath string, configDir string) error {
	return vkturncore.StartVkTurnClient(configJsonBase64, logPath, configDir)
}

// StopVkTurnClient stops the running VK TURN client.
func StopVkTurnClient() error {
	return vkturncore.StopVkTurnClient()
}

// IsVkTurnClientRunning returns whether the client is currently running.
func IsVkTurnClientRunning() bool {
	return vkturncore.IsVkTurnClientRunning()
}

// GetVkTurnLocalPort returns the local listening port.
func GetVkTurnLocalPort() int {
	return vkturncore.GetVkTurnLocalPort()
}

// GetVkTurnActiveStreams returns the number of currently active/connected VK TURN streams.
func GetVkTurnActiveStreams() int {
	return vkturncore.GetVkTurnActiveStreams()
}

// GetVkTurnLastError returns the last fatal error message, if any.
func GetVkTurnLastError() string {
	return vkturncore.GetVkTurnLastError()
}

// CaptchaHandler defines callback interface for manual captcha solving.
type CaptchaHandler interface {
	OpenCaptcha(url string)
}

// SetCaptchaHandler sets the callback for manual captcha UI.
func SetCaptchaHandler(h CaptchaHandler) {
	vkturncore.SetCaptchaHandler(h)
}

// SubmitCaptchaToken submits the solved captcha token from Android UI.
func SubmitCaptchaToken(token string) {
	vkturncore.SubmitCaptchaToken(token)
}


