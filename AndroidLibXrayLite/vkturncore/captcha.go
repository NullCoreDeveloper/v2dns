package vkturncore

import (
	"context"
	"net"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
)

// Backward-compatible type aliases
type VkCaptchaError = CaptchaError

// ParseVkCaptchaError is an alias for ParseCaptchaError for backward compatibility.
func ParseVkCaptchaError(errData map[string]interface{}) *VkCaptchaError {
	return ParseCaptchaError(errData)
}

func applyBrowserProfileFhttp(req *fhttp.Request, profile Profile) {
	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("sec-ch-ua", profile.SecChUa)
	req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,ru;q=0.8")
	req.Header.Set("DNT", "1")
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
