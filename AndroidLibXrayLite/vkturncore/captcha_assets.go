package vkturncore

import (
	neturl "net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	fhttp "github.com/bogdanfinn/fhttp"
)

const (
	assetsMaxParallel = 6
	assetsMaxCount    = 40
)

var (
	reAssetScript = regexp.MustCompile(`<script[^>]+src="([^"]+)"`)
	reAssetLink   = regexp.MustCompile(`<link[^>]+>`)
	reAssetHref   = regexp.MustCompile(`href="([^"]+)"`)
	reAssetRel    = regexp.MustCompile(`rel="([^"]+)"`)
	reAssetAs     = regexp.MustCompile(`as="([^"]+)"`)
	reAssetImg    = regexp.MustCompile(`<img[^>]+src="([^"]+)"`)
)

type captchaAsset struct {
	URL  string
	Dest string
}

func parsePageAssets(html string) []captchaAsset {
	seen := map[string]struct{}{}
	out := make([]captchaAsset, 0, assetsMaxCount)

	add := func(raw, dest string) {
		url := absoluteAssetURL(raw)
		if url == "" || len(out) >= assetsMaxCount {
			return
		}
		if _, dup := seen[url]; dup {
			return
		}
		seen[url] = struct{}{}
		out = append(out, captchaAsset{URL: url, Dest: dest})
	}

	for _, m := range reAssetScript.FindAllStringSubmatch(html, -1) {
		add(m[1], "script")
	}
	for _, tag := range reAssetLink.FindAllString(html, -1) {
		href := reAssetHref.FindStringSubmatch(tag)
		if len(href) < 2 {
			continue
		}
		add(href[1], linkDest(tag))
	}
	for _, m := range reAssetImg.FindAllStringSubmatch(html, -1) {
		add(m[1], "image")
	}
	return out
}

func linkDest(tag string) string {
	if as := reAssetAs.FindStringSubmatch(tag); len(as) > 1 {
		return as[1]
	}
	rel := ""
	if m := reAssetRel.FindStringSubmatch(tag); len(m) > 1 {
		rel = m[1]
	}
	switch {
	case strings.Contains(rel, "stylesheet"):
		return "style"
	case strings.Contains(rel, "icon"):
		return "image"
	default:
		return "empty"
	}
}

var assetHostSuffixes = []string{".vk.com", ".vk.ru", ".userapi.com", ".okcdn.ru", ".mycdn.me"}

func absoluteAssetURL(raw string) string {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "https://"):
	case strings.HasPrefix(raw, "//"):
		raw = "https:" + raw
	default:
		return ""
	}
	u, err := neturl.Parse(raw)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	for _, suffix := range assetHostSuffixes {
		if strings.HasSuffix(host, suffix) {
			return raw
		}
	}
	return ""
}

func (s *captchaSession) loadAssets(assets []captchaAsset) {
	if len(assets) == 0 {
		return
	}
	limit := min(len(assets), assetsMaxParallel)
	ch := make(chan captchaAsset, len(assets))
	for _, a := range assets {
		ch <- a
	}
	close(ch)

	var okCount atomic.Int32
	var failCount atomic.Int32
	var wg sync.WaitGroup
	for range limit {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range ch {
				if s.ctx.Err() != nil {
					return
				}
				if err := s.fetchAsset(a); err == nil {
					okCount.Add(1)
				} else {
					failCount.Add(1)
				}
			}
		}()
	}
	wg.Wait()
}

func (s *captchaSession) fetchAsset(a captchaAsset) error {
	headers := map[string]string{
		"Sec-Fetch-Site": "cross-site",
		"Sec-Fetch-Mode": "no-cors",
		"Sec-Fetch-Dest": a.Dest,
		"Referer":        s.pageOrigin + "/",
	}
	if u, err := neturl.Parse(a.URL); err == nil && u.Scheme+"://"+u.Host == s.pageOrigin {
		headers["Sec-Fetch-Site"] = "same-origin"
		headers["Referer"] = s.pageURL
	}
	_, err := s.doRaw(fhttp.MethodGet, a.URL, nil, headers)
	return err
}
