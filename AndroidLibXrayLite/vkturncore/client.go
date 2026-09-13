package vkturncore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	neturl "net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/google/uuid"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/transport/v4"
	"github.com/pion/turn/v5"
	"github.com/xtaci/smux"
)

type VKCredentials struct {
	ClientID     string
	ClientSecret string
}

var defaultVkCredentials = []VKCredentials{
	{ClientID: "6287487", ClientSecret: "QbYic1K3lEV5kTGiqlq2"},  // VK Web
	{ClientID: "7879029", ClientSecret: "aR5NKGmm03GYrCiNKsaw"},  // VK MVK
	{ClientID: "2274003", ClientSecret: "hHbZxrka2uZ6jB1inYsH"},  // VK Android
	{ClientID: "51453752", ClientSecret: "4UyuCUsdK8pVCNoeQuGi"}, // VK Desktop
	{ClientID: "3140623", ClientSecret: "VeWdmVclDCtn6ihuP1nt"},  // VK iOS
}

const vkApiVersion = "5.282"

var (
	ErrInvalidJoinLink = errors.New("INVALID_JOIN_LINK: join link is expired or not valid (VK error 9008)")
	lastVkTurnError    string
	lastErrorMu        sync.RWMutex
)

func setVkTurnLastError(errStr string) {
	lastErrorMu.Lock()
	lastVkTurnError = errStr
	lastErrorMu.Unlock()
}

// GetVkTurnLastError returns the last fatal error message, if any.
func GetVkTurnLastError() string {
	lastErrorMu.RLock()
	defer lastErrorMu.RUnlock()
	return lastVkTurnError
}

func isFatalLinkError(errObj map[string]interface{}) bool {
	code := 0
	if c, ok := errObj["error_code"].(float64); ok {
		code = int(c)
	} else if c, ok := errObj["error_code"].(int); ok {
		code = c
	}
	msg := ""
	if m, ok := errObj["error_msg"].(string); ok {
		msg = strings.ToLower(m)
	}
	if code == 9000 || code == 9008 || strings.Contains(msg, "not valid") || strings.Contains(msg, "not found") {
		return true
	}
	return false
}

type ClientConfig struct {
	Server         string `json:"server"`
	Port           int    `json:"port"`
	TargetProtocol string `json:"targetProtocol"`
	VkLink         string `json:"vkLink"`
	Streams        int    `json:"streams"`
	VkAppId        string `json:"vkAppId"`
	VkAppSecret    string `json:"vkAppSecret"`
	ClientId       string `json:"clientId"`
	ClientPassword string `json:"clientPassword"`
	LocalPort      int    `json:"localPort"`
}

type sessionPool struct {
	sessions []*smux.Session
	current  int
	mu       sync.RWMutex
}

func (p *sessionPool) add(s *smux.Session) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sessions = append(p.sessions, s)
}

func (p *sessionPool) remove(s *smux.Session) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, sess := range p.sessions {
		if sess == s {
			p.sessions = append(p.sessions[:i], p.sessions[i+1:]...)
			break
		}
	}
}

func (p *sessionPool) count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.sessions)
}

func (p *sessionPool) pick() *smux.Session {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.sessions) == 0 {
		return nil
	}
	s := p.sessions[p.current%len(p.sessions)]
	p.current++
	return s
}

func (p *sessionPool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.sessions {
		_ = s.Close()
	}
	p.sessions = nil
}

type dtlsPool struct {
	mu    sync.RWMutex
	conns []net.Conn
}

func (p *dtlsPool) add(c net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.conns = append(p.conns, c)
}

func (p *dtlsPool) remove(c net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, conn := range p.conns {
		if conn == c {
			p.conns = append(p.conns[:i], p.conns[i+1:]...)
			break
		}
	}
}

func (p *dtlsPool) count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.conns)
}

// pick returns the primary (first) connection for sticky routing.
// WireGuard requires all packets to flow through a single transport path
// to avoid reordering, which would cause the kernel to drop packets.
func (p *dtlsPool) pick() net.Conn {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.conns) == 0 {
		return nil
	}
	return p.conns[0]
}

func (p *dtlsPool) isAlive(c net.Conn) bool {
	if c == nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, conn := range p.conns {
		if conn == c {
			return true
		}
	}
	return false
}

func (p *dtlsPool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		_ = c.Close()
	}
	p.conns = nil
}

// Global Client Runtime State
var (
	clientMu         sync.Mutex
	clientRunning    bool
	clientCancel     context.CancelFunc
	activeListener   net.Listener
	activePacketConn net.PacketConn
	activePool       *sessionPool
	activeDtlsPool   *dtlsPool
	activeLocalPort  int
	globalLockout    atomic.Int64
	activeClientAddr atomic.Value // holds net.Addr
	activeWg         sync.WaitGroup
)

type turnCachedCreds struct {
	username    string
	password    string
	serverAddrs []string
	link        string
	expiresAt   time.Time
}

const defaultStreamsPerCache = 12

var (
	credsCacheMu sync.RWMutex
	cachedCreds  = make(map[int]turnCachedCreds) // cacheIndex -> credentials
	vkFetchSem   = make(chan struct{}, 1)
)

type allocPacer struct {
	mu   sync.Mutex
	next time.Time
	step time.Duration
}

var globalAllocPacer = &allocPacer{step: 200 * time.Millisecond}

func (p *allocPacer) Wait(ctx context.Context) bool {
	if p == nil {
		return ctx.Err() == nil
	}
	wait := time.Until(p.slot())
	if wait <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (p *allocPacer) slot() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.next.Before(now) {
		p.next = now
	}
	slot := p.next
	p.next = slot.Add(p.step)
	return slot
}

func getCacheIndex(streamID int) int {
	if streamID <= 1 {
		return 0
	}
	return (streamID - 1) / defaultStreamsPerCache
}

func orderAddrs(addrs []string, streamID int) []string {
	n := len(addrs)
	if n <= 1 {
		return append([]string(nil), addrs...)
	}
	k := (streamID - 1) % n
	if k < 0 {
		k = 0
	}
	out := make([]string, 0, n)
	out = append(out, addrs[k:]...)
	out = append(out, addrs[:k]...)
	return out
}

func invalidateCachedCreds(link string, streamID int) {
	cIdx := getCacheIndex(streamID)
	credsCacheMu.Lock()
	delete(cachedCreds, cIdx)
	credsCacheMu.Unlock()
	log.Printf("[STREAM %d] [VK Auth] Invalidated cached TURN credentials for cache %d", streamID, cIdx)
}

func clearAllCachedCreds() {
	credsCacheMu.Lock()
	cachedCreds = make(map[int]turnCachedCreds)
	credsCacheMu.Unlock()
}

func cleanVkLink(link string) string {
	link = strings.TrimSpace(link)
	if parts := strings.Split(link, "join/"); len(parts) > 1 {
		link = parts[len(parts)-1]
	} else if parts := strings.Split(link, "call/"); len(parts) > 1 {
		link = parts[len(parts)-1]
	}
	if idx := strings.IndexAny(link, "/?#&"); idx != -1 {
		link = link[:idx]
	}
	return strings.TrimSpace(link)
}

// directNet implements Pion transport.Net interface
type directNet struct{}
type directDialer struct{ *net.Dialer }
type directListenConfig struct{ *net.ListenConfig }
type directTCPListener struct{ *net.TCPListener }

func (directNet) ListenPacket(network string, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address)
}
func (directNet) ListenUDP(network string, locAddr *net.UDPAddr) (transport.UDPConn, error) {
	return net.ListenUDP(network, locAddr)
}
func (directNet) ListenTCP(network string, laddr *net.TCPAddr) (transport.TCPListener, error) {
	l, err := net.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}
	return directTCPListener{l}, nil
}
func (directNet) Dial(network, address string) (net.Conn, error) {
	return net.Dial(network, address)
}
func (directNet) DialUDP(network string, laddr, raddr *net.UDPAddr) (transport.UDPConn, error) {
	return net.DialUDP(network, laddr, raddr)
}
func (directNet) DialTCP(network string, laddr, raddr *net.TCPAddr) (transport.TCPConn, error) {
	return net.DialTCP(network, laddr, raddr)
}
func (directNet) ResolveIPAddr(network, address string) (*net.IPAddr, error) {
	return net.ResolveIPAddr(network, address)
}
func (directNet) ResolveUDPAddr(network, address string) (*net.UDPAddr, error) {
	return net.ResolveUDPAddr(network, address)
}
func (directNet) ResolveTCPAddr(network, address string) (*net.TCPAddr, error) {
	return net.ResolveTCPAddr(network, address)
}
func (directNet) Interfaces() ([]*transport.Interface, error) {
	return nil, transport.ErrNotSupported
}
func (directNet) InterfaceByIndex(index int) (*transport.Interface, error) {
	return nil, fmt.Errorf("%w: index=%d", transport.ErrInterfaceNotFound, index)
}
func (directNet) InterfaceByName(name string) (*transport.Interface, error) {
	return nil, fmt.Errorf("%w: %s", transport.ErrInterfaceNotFound, name)
}
func (directNet) CreateDialer(dialer *net.Dialer) transport.Dialer {
	return directDialer{Dialer: dialer}
}
func (directNet) CreateListenConfig(listenerConfig *net.ListenConfig) transport.ListenConfig {
	return directListenConfig{ListenConfig: listenerConfig}
}
func (d directDialer) Dial(network, address string) (net.Conn, error) {
	return d.Dialer.Dial(network, address)
}
func (d directListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return d.ListenConfig.Listen(ctx, network, address)
}
func (d directListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return d.ListenConfig.ListenPacket(ctx, network, address)
}
func (l directTCPListener) AcceptTCP() (transport.TCPConn, error) {
	return l.TCPListener.AcceptTCP()
}

type connectedUDPConn struct {
	*net.UDPConn
}

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}

type relayPacketConn struct {
	relay net.PacketConn
	peer  net.Addr
}

func (r *relayPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return r.relay.ReadFrom(b)
}
func (r *relayPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return r.relay.WriteTo(b, r.peer)
}
func (r *relayPacketConn) Close() error                       { return r.relay.Close() }
func (r *relayPacketConn) LocalAddr() net.Addr                { return r.relay.LocalAddr() }
func (r *relayPacketConn) SetDeadline(t time.Time) error      { return r.relay.SetDeadline(t) }
func (r *relayPacketConn) SetReadDeadline(t time.Time) error  { return r.relay.SetReadDeadline(t) }
func (r *relayPacketConn) SetWriteDeadline(t time.Time) error { return r.relay.SetWriteDeadline(t) }

func fetchVkCreds(ctx context.Context, link string, customCred *VKCredentials, streamID int) (string, string, []string, error) {
	if time.Now().Unix() < globalLockout.Load() {
		return "", "", nil, fmt.Errorf("CAPTCHA_WAIT_REQUIRED: global lockout active")
	}

	cIdx := getCacheIndex(streamID)

	credsCacheMu.RLock()
	if c, ok := cachedCreds[cIdx]; ok && c.link == link && time.Now().Before(c.expiresAt) && len(c.serverAddrs) > 0 {
		u, p := c.username, c.password
		addrs := orderAddrs(c.serverAddrs, streamID)
		credsCacheMu.RUnlock()
		log.Printf("[STREAM %d] [VK Auth] Using cached TURN credentials (cache=%d, expires in %v, server=%s)", streamID, cIdx, time.Until(c.expiresAt).Round(time.Second), addrs[0])
		return u, p, addrs, nil
	}
	select {
	case <-ctx.Done():
		return "", "", nil, ctx.Err()
	case vkFetchSem <- struct{}{}:
		defer func() { <-vkFetchSem }()
	}

	// Double-check inside lock
	credsCacheMu.RLock()
	if c, ok := cachedCreds[cIdx]; ok && c.link == link && time.Now().Before(c.expiresAt) && len(c.serverAddrs) > 0 {
		u, p := c.username, c.password
		addrs := orderAddrs(c.serverAddrs, streamID)
		credsCacheMu.RUnlock()
		return u, p, addrs, nil
	}
	credsCacheMu.RUnlock()

	credsList := defaultVkCredentials
	if customCred != nil && customCred.ClientID != "" && customCred.ClientSecret != "" {
		credsList = append([]VKCredentials{*customCred}, credsList...)
	}

	jar := tlsclient.NewCookieJar()
	var lastErr error

	for _, creds := range credsList {
		user, pass, addrs, err := getTokenChain(ctx, link, creds, streamID, jar)
		if err == nil {
			credsCacheMu.Lock()
			cachedCreds[cIdx] = turnCachedCreds{
				username:    user,
				password:    pass,
				serverAddrs: addrs,
				link:        link,
				expiresAt:   time.Now().Add(9 * time.Minute),
			}
			credsCacheMu.Unlock()
			ordered := orderAddrs(addrs, streamID)
			log.Printf("[STREAM %d] [VK Auth] Registered new credentials (cache=%d, user=%s) with %d servers, target=%s", streamID, cIdx, user, len(addrs), ordered[0])
			return user, pass, ordered, nil
		}
		lastErr = err
		log.Printf("[STREAM %d] [VK Auth] Creds failed (%s): %v", streamID, creds.ClientID, err)
		if errors.Is(err, ErrInvalidJoinLink) {
			errMsg := "Ссылка на звонок VK недействительна или звонок завершён (код 9008). Создайте новый звонок на vk.com/calls и укажите новую ссылку в конфиге!"
			setVkTurnLastError(errMsg)
			log.Printf("[STREAM %d] [VK Auth] FATAL: %s", streamID, errMsg)
			return "", "", nil, ErrInvalidJoinLink
		}
	}

	return "", "", nil, fmt.Errorf("all VK credentials failed for cache %d: %w", cIdx, lastErr)
}

func getTokenChain(ctx context.Context, link string, creds VKCredentials, streamID int, jar tlsclient.CookieJar) (string, string, []string, error) {
	profile := getRandomProfile()
	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(15),
		tlsclient.WithClientProfile(profiles.Chrome_146),
		tlsclient.WithCookieJar(jar),
		tlsclient.WithDialer(getCustomNetDialer()),
	)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to init tls_client: %w", err)
	}

	name := generateName()
	escapedName := neturl.QueryEscape(name)

	captchaPlatform := CaptchaPlatformDesktop
	if profile.SecChUaMobile == "?1" {
		captchaPlatform = CaptchaPlatformMobile
	}
	captchaProfile := ProfileFor(captchaPlatform, CaptchaIdentity{Seed: name, Gen: 0})

	doRequest := func(data, url string) (map[string]interface{}, error) {
		parsedURL, err := neturl.Parse(url)
		if err != nil {
			return nil, err
		}

		req, err := fhttp.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}

		req.Host = parsedURL.Hostname()
		applyBrowserProfileFhttp(req, profile)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Origin", "https://vk.ru")
		req.Header.Set("Referer", "https://vk.ru/")
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

	// 1. Get anon token
	data := fmt.Sprintf("client_id=%s&token_type=messages&client_secret=%s&version=1&app_id=%s", creds.ClientID, creds.ClientSecret, creds.ClientID)
	resp, err := doRequest(data, "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return "", "", nil, err
	}
	dataMap, ok := resp["data"].(map[string]interface{})
	if !ok {
		return "", "", nil, fmt.Errorf("invalid anon token response")
	}
	token1, ok := dataMap["access_token"].(string)
	if !ok {
		return "", "", nil, fmt.Errorf("missing access_token")
	}

	select {
	case <-ctx.Done():
		return "", "", nil, ctx.Err()
	case <-time.After(100 * time.Millisecond):
	}

	// 2. Call preview
	data = fmt.Sprintf("vk_join_link=https://vk.ru/call/join/%s&fields=photo_200&access_token=%s", link, token1)
	previewResp, _ := doRequest(data, "https://api.vk.ru/method/calls.getCallPreview?v="+vkApiVersion+"&client_id="+creds.ClientID)
	if previewErrObj, hasErr := previewResp["error"].(map[string]interface{}); hasErr {
		if isFatalLinkError(previewErrObj) {
			return "", "", nil, ErrInvalidJoinLink
		}
	}

	select {
	case <-ctx.Done():
		return "", "", nil, ctx.Err()
	case <-time.After(200 * time.Millisecond):
	}

	// 3. Get Anonymous Token
	data = fmt.Sprintf("vk_join_link=https://vk.ru/call/join/%s&name=%s&access_token=%s", link, escapedName, token1)
	urlAddr := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=%s&client_id=%s", vkApiVersion, creds.ClientID)

	var token2 string
	for attempt := 0; attempt < 3; attempt++ {
		resp, err = doRequest(data, urlAddr)
		if err != nil {
			return "", "", nil, err
		}

		if errObj, hasErr := resp["error"].(map[string]interface{}); hasErr {
			captchaErr := ParseVkCaptchaError(errObj)
			if captchaErr != nil && captchaErr.IsCaptchaError() {
				successToken, solveErr := SolveCaptcha(ctx, captchaErr, streamID, client, captchaProfile)
				if solveErr != nil {
					log.Printf("[STREAM %d] [VK Captcha] Auto solve failed: %v. Triggering manual captcha fallback...", streamID, solveErr)
					var manualErr error
					if captchaErr.RedirectURI != "" {
						successToken, manualErr = solveCaptchaViaProxy(ctx, captchaErr.RedirectURI)
					}
					if manualErr != nil {
						globalLockout.Store(time.Now().Add(10 * time.Second).Unix())
						return "", "", nil, fmt.Errorf("manual captcha failed: %w", manualErr)
					}
				}
				data = fmt.Sprintf("vk_join_link=https://vk.ru/call/join/%s&name=%s&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%s&captcha_attempt=%s&access_token=%s",
					link, escapedName, captchaErr.CaptchaSid, neturl.QueryEscape(successToken), captchaErr.CaptchaTs, captchaErr.CaptchaAttempt, token1)
				continue
			}
			if isFatalLinkError(errObj) {
				return "", "", nil, ErrInvalidJoinLink
			}
			return "", "", nil, fmt.Errorf("VK API error: %v", errObj)
		}

		respMap, okLoop := resp["response"].(map[string]interface{})
		if !okLoop {
			return "", "", nil, fmt.Errorf("unexpected getAnonymousToken response")
		}
		token2, okLoop = respMap["token"].(string)
		if !okLoop {
			return "", "", nil, fmt.Errorf("missing token2 in response")
		}
		break
	}

	select {
	case <-ctx.Done():
		return "", "", nil, ctx.Err()
	case <-time.After(100 * time.Millisecond):
	}

	// 4. OK Login
	sessionData := fmt.Sprintf(`{"version":2,"device_id":"%s","client_version":1.1,"client_type":"SDK_JS"}`, uuid.New())
	data = fmt.Sprintf("session_data=%s&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA", neturl.QueryEscape(sessionData))
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", nil, err
	}
	token3, ok := resp["session_key"].(string)
	if !ok {
		return "", "", nil, fmt.Errorf("missing session_key in response")
	}

	select {
	case <-ctx.Done():
		return "", "", nil, ctx.Err()
	case <-time.After(100 * time.Millisecond):
	}

	// 5. Join Conversation -> TURN Credentials
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&capabilities=2F7F&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, token2, token3)
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", nil, err
	}

	tsRaw, ok := resp["turn_server"].(map[string]interface{})
	if !ok {
		return "", "", nil, fmt.Errorf("missing turn_server in response: %v", resp)
	}
	user, _ := tsRaw["username"].(string)
	pass, _ := tsRaw["credential"].(string)
	urlsRaw, ok := tsRaw["urls"].([]interface{})
	if !ok || len(urlsRaw) == 0 {
		return "", "", nil, fmt.Errorf("missing urls in turn_server")
	}

	var addresses []string
	for _, u := range urlsRaw {
		urlStr, ok := u.(string)
		if !ok {
			continue
		}
		clean := strings.Split(urlStr, "?")[0]
		addr := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")
		if addr != "" {
			addresses = append(addresses, addr)
		}
	}
	if len(addresses) == 0 {
		return "", "", nil, fmt.Errorf("no valid TURN addresses in turn_server.urls")
	}
	log.Printf("[STREAM %d] [VK Auth] Discovered %d TURN servers in pool: %v", streamID, len(addresses), addresses)

	return user, pass, addresses, nil
}

func createRawDtlsConn(ctx context.Context, cfg *ClientConfig, peer *net.UDPAddr, streamID int) (net.Conn, func(), error) {
	var cleanupFns []func()
	cleanup := func() {
		for i := len(cleanupFns) - 1; i >= 0; i-- {
			cleanupFns[i]()
		}
	}

	var customCred *VKCredentials
	if cfg.VkAppId != "" && cfg.VkAppSecret != "" {
		customCred = &VKCredentials{ClientID: cfg.VkAppId, ClientSecret: cfg.VkAppSecret}
	} else if cfg.ClientId != "" && cfg.ClientPassword != "" && !strings.Contains(cfg.ClientId, "-") {
		customCred = &VKCredentials{ClientID: cfg.ClientId, ClientSecret: cfg.ClientPassword}
	}

	user, pass, turnAddrs, err := fetchVkCreds(ctx, cfg.VkLink, customCred, streamID)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch TURN creds: %w", err)
	}

	if len(turnAddrs) == 0 {
		return nil, nil, fmt.Errorf("no TURN servers available in pool")
	}

	var addrFamily turn.RequestedAddressFamily = turn.RequestedAddressFamilyIPv4
	if peer.IP.To4() == nil {
		addrFamily = turn.RequestedAddressFamilyIPv6
	}

	var relayConn net.PacketConn
	var candidateErrs []string

	for candIdx, candAddr := range turnAddrs {
		turnUDPAddr, err := net.ResolveUDPAddr("udp", candAddr)
		if err != nil {
			candidateErrs = append(candidateErrs, fmt.Sprintf("%s (resolve: %v)", candAddr, err))
			continue
		}

		c, err := net.DialUDP("udp", nil, turnUDPAddr)
		if err != nil {
			candidateErrs = append(candidateErrs, fmt.Sprintf("%s (dial: %v)", candAddr, err))
			continue
		}
		turnConn := &connectedUDPConn{c}

		turnClient, err := turn.NewClient(&turn.ClientConfig{
			STUNServerAddr:            candAddr,
			TURNServerAddr:            candAddr,
			Conn:                      turnConn,
			Net:                       directNet{},
			Username:                  user,
			Password:                  pass,
			RequestedAddressFamily:    addrFamily,
			PermissionRefreshInterval: 24 * time.Hour,
			LoggerFactory:             logging.NewDefaultLoggerFactory(),
		})
		if err != nil {
			_ = c.Close()
			candidateErrs = append(candidateErrs, fmt.Sprintf("%s (client init: %v)", candAddr, err))
			continue
		}

		if err = turnClient.Listen(); err != nil {
			turnClient.Close()
			_ = c.Close()
			candidateErrs = append(candidateErrs, fmt.Sprintf("%s (listen: %v)", candAddr, err))
			continue
		}

		if !globalAllocPacer.Wait(ctx) {
			turnClient.Close()
			_ = c.Close()
			return nil, nil, ctx.Err()
		}

		// Allocate() has no context parameter — run in goroutine so that
		// ctx cancellation (Stop) can interrupt it by closing the UDP conn and client.
		type allocResult struct {
			conn net.PacketConn
			err  error
		}
		allocCh := make(chan allocResult, 1)
		go func() {
			rc, re := turnClient.Allocate()
			select {
			case allocCh <- allocResult{rc, re}:
			default:
				if rc != nil {
					_ = rc.Close()
				}
			}
		}()
		var ar allocResult
		select {
		case ar = <-allocCh:
		case <-ctx.Done():
			turnClient.Close()
			_ = c.Close()
			return nil, nil, ctx.Err()
		}
		if ar.err != nil {
			turnClient.Close()
			_ = c.Close()
			candidateErrs = append(candidateErrs, fmt.Sprintf("%s (allocate: %v)", candAddr, ar.err))
			if candIdx < len(turnAddrs)-1 {
				log.Printf("[STREAM %d] TURN candidate %s failed (%v), trying next server...", streamID, candAddr, ar.err)
			}
			continue
		}
		rConn := ar.conn

		relayConn = rConn
		cleanupFns = append(cleanupFns, func() { _ = rConn.Close() })
		cleanupFns = append(cleanupFns, func() { turnClient.Close() })
		cleanupFns = append(cleanupFns, func() { _ = c.Close() })
		log.Printf("[STREAM %d] Successfully allocated TURN relay on %s (candidate %d/%d)", streamID, candAddr, candIdx+1, len(turnAddrs))
		break
	}

	if relayConn == nil {
		invalidateCachedCreds(cfg.VkLink, streamID)
		return nil, nil, fmt.Errorf("all TURN candidates failed: %s", strings.Join(candidateErrs, "; "))
	}

	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("generate TLS cert: %w", err)
	}

	dtlsPC := &relayPacketConn{relay: relayConn, peer: peer}
	dtlsConn, err := dtls.ClientWithOptions(dtlsPC, peer,
		dtls.WithCertificates(cert),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithConnectionIDGenerator(dtls.OnlySendCIDGenerator()),
	)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("DTLS client: %w", err)
	}

	handshakeCtx, handshakeCancel := context.WithTimeout(ctx, 25*time.Second)
	defer handshakeCancel()

	handshakeDone := make(chan struct{})
	go func() {
		select {
		case <-handshakeCtx.Done():
			if ctx.Err() != nil {
				_ = dtlsConn.Close()
				_ = relayConn.Close()
			}
		case <-handshakeDone:
		}
	}()

	if err = dtlsConn.HandshakeContext(handshakeCtx); err != nil {
		close(handshakeDone)
		_ = dtlsConn.Close()
		cleanup()
		return nil, nil, fmt.Errorf("DTLS handshake: %w", err)
	}
	close(handshakeDone)
	cleanupFns = append(cleanupFns, func() { _ = dtlsConn.Close() })

	return dtlsConn, cleanup, nil
}

func createSmuxSession(ctx context.Context, cfg *ClientConfig, peer *net.UDPAddr, streamID int) (*smux.Session, func(), error) {
	dtlsConn, dtlsCleanup, err := createRawDtlsConn(ctx, cfg, peer, streamID)
	if err != nil {
		return nil, nil, err
	}

	var cleanupFns []func()
	cleanupFns = append(cleanupFns, dtlsCleanup)
	cleanup := func() {
		for i := len(cleanupFns) - 1; i >= 0; i-- {
			cleanupFns[i]()
		}
	}

	kcpSess, err := NewKCPOverDTLS(dtlsConn, false)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("KCP init: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { _ = kcpSess.Close() })

	smuxSess, err := smux.Client(kcpSess, DefaultSmuxConfig())
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("smux init: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { _ = smuxSess.Close() })

	return smuxSess, cleanup, nil
}

func maintainDtlsSession(ctx context.Context, cfg *ClientConfig, peer *net.UDPAddr, id int, pool *dtlsPool, pc net.PacketConn) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, cleanup, err := createRawDtlsConn(ctx, cfg, peer, id)
		if err != nil {
			retryDelay := 3 * time.Second
			if errors.Is(err, ErrInvalidJoinLink) {
				log.Printf("[STREAM %d] Setup DTLS error: VK call link is invalid or expired. Waiting 30s...", id)
				retryDelay = 30 * time.Second
			} else {
				log.Printf("[STREAM %d] Setup DTLS error: %v, retrying in 3s...", id, err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(retryDelay):
			}
			continue
		}

		pool.add(conn)
		log.Printf("[STREAM %d] Connected to VK TURN UDP tunnel (active: %d)", id, pool.count())

		rxDone := make(chan struct{})
		go func(c net.Conn) {
			defer close(rxDone)
			rxBuf := make([]byte, 65535)
			for {
				n, rErr := c.Read(rxBuf)
				if rErr != nil {
					return
				}
				if ca := activeClientAddr.Load(); ca != nil {
					if targetAddr, ok := ca.(net.Addr); ok {
						_, _ = pc.WriteTo(rxBuf[:n], targetAddr)
					}
				}
			}
		}(conn)

		select {
		case <-ctx.Done():
			pool.remove(conn)
			cleanup()
			return
		case <-rxDone:
		}

		pool.remove(conn)
		cleanup()
		log.Printf("[STREAM %d] Disconnected from VK TURN UDP tunnel, reconnecting...", id)

		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func maintainSession(ctx context.Context, cfg *ClientConfig, peer *net.UDPAddr, id int, pool *sessionPool) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		sess, cleanup, err := createSmuxSession(ctx, cfg, peer, id)
		if err != nil {
			retryDelay := 3 * time.Second
			if errors.Is(err, ErrInvalidJoinLink) {
				log.Printf("[STREAM %d] Setup error: VK call link is invalid or expired. Waiting 30s...", id)
				retryDelay = 30 * time.Second
			} else {
				log.Printf("[STREAM %d] Setup error: %v, retrying in 3s...", id, err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(retryDelay):
			}
			continue
		}

		pool.add(sess)
		log.Printf("[STREAM %d] Connected to VK TURN tunnel (active: %d)", id, pool.count())

		for !sess.IsClosed() {
			select {
			case <-ctx.Done():
				pool.remove(sess)
				cleanup()
				return
			case <-time.After(1 * time.Second):
			}
		}

		pool.remove(sess)
		cleanup()
		log.Printf("[STREAM %d] Disconnected from VK TURN tunnel, reconnecting...", id)

		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func pipe(ctx context.Context, c1, c2 net.Conn) {
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()

	var once sync.Once
	closeBoth := func() {
		_ = c1.Close()
		_ = c2.Close()
	}

	context.AfterFunc(ctx2, closeBoth)

	var wg sync.WaitGroup
	wg.Add(2)

	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		time.AfterFunc(5*time.Second, func() {
			once.Do(closeBoth)
		})
	}

	go cp(c1, c2)
	go cp(c2, c1)

	wg.Wait()
	once.Do(closeBoth)
}

func stopVkTurnClientLocked() {
	if clientCancel != nil {
		clientCancel()
		clientCancel = nil
	}
	if activeListener != nil {
		_ = activeListener.Close()
		activeListener = nil
	}
	if activePacketConn != nil {
		_ = activePacketConn.Close()
		activePacketConn = nil
	}
	if activeDtlsPool != nil {
		activeDtlsPool.closeAll()
		activeDtlsPool = nil
	}
	if activePool != nil {
		activePool.closeAll()
		activePool = nil
	}
	clientRunning = false
	activeLocalPort = 0
	activeClientAddr.Store(nil)
	globalLockout.Store(0)
	clearAllCachedCreds()
}

// StartVkTurnClient starts the VK TURN client tunnel.
func StartVkTurnClient(configJsonBase64 string, logPath string, configDir string) error {
	clientMu.Lock()
	defer clientMu.Unlock()

	globalConfigDir = configDir
	setVkTurnLastError("")

	if clientRunning {
		log.Printf("[VK TURN Client] Existing client is running, stopping it before starting new one...")
		stopVkTurnClientLocked()
	}

	data, err := base64.StdEncoding.DecodeString(configJsonBase64)
	if err != nil {
		return fmt.Errorf("failed to decode base64 config: %w", err)
	}

	var cfg ClientConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse client config JSON: %w", err)
	}

	if cfg.Server == "" || cfg.Port == 0 {
		return fmt.Errorf("invalid server address (%s:%d)", cfg.Server, cfg.Port)
	}
	cfg.VkLink = cleanVkLink(cfg.VkLink)
	if cfg.VkLink == "" {
		cfg.VkLink = "aD0YV1u9x_8m51L9H4fQ_6_16089" // fallback default conference link
	}
	if cfg.Streams <= 0 {
		cfg.Streams = 10
	}
	if cfg.Streams > 16 {
		cfg.Streams = 16
	}

	peerAddr := fmt.Sprintf("%s:%d", cfg.Server, cfg.Port)
	peerUDP, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve target server %s: %w", peerAddr, err)
	}

	isWireguard := (cfg.TargetProtocol == "wireguard" || cfg.TargetProtocol == "udp" || cfg.TargetProtocol == "")

	ctx, cancel := context.WithCancel(context.Background())
	clientCancel = cancel
	clientRunning = true

	if isWireguard {
		listenAddr := fmt.Sprintf("127.0.0.1:%d", cfg.LocalPort)
		pc, err := net.ListenPacket("udp", listenAddr)
		if err != nil {
			cancel()
			clientRunning = false
			return fmt.Errorf("failed to listen UDP on %s: %w", listenAddr, err)
		}

		udpAddr, _ := pc.LocalAddr().(*net.UDPAddr)
		activeLocalPort = udpAddr.Port
		activePacketConn = pc
		log.Printf("[VK TURN Client] Listening UDP on 127.0.0.1:%d for WireGuard traffic to %s (streams: %d)", activeLocalPort, peerAddr, cfg.Streams)

		pool := &dtlsPool{}
		activeDtlsPool = pool

		// Staggered session maintenance goroutines
		for i := 0; i < cfg.Streams; i++ {
			activeWg.Add(1)
			go func(id int) {
				defer activeWg.Done()
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(id) * 350 * time.Millisecond):
				}
				maintainDtlsSession(ctx, &cfg, peerUDP, id+1, pool, pc)
			}(i)
		}

		// Local UDP forwarder loop
		go func(conn net.PacketConn, c context.Context) {
			defer func() {
				_ = conn.Close()
				clientMu.Lock()
				if activePacketConn == conn {
					clientRunning = false
					clientCancel = nil
					activePacketConn = nil
					activeLocalPort = 0
					if activeDtlsPool != nil {
						activeDtlsPool.closeAll()
						activeDtlsPool = nil
					}
				}
				clientMu.Unlock()
			}()

			buf := make([]byte, 65535)
			var stickyConn net.Conn
			for {
				n, srcAddr, rErr := conn.ReadFrom(buf)
				if rErr != nil {
					return
				}
				activeClientAddr.Store(srcAddr)

				// Ensure stickyConn is non-nil and still alive in the active pool
				if stickyConn == nil || !pool.isAlive(stickyConn) {
					stickyConn = pool.pick()
				}
				if stickyConn != nil {
					if _, werr := stickyConn.Write(buf[:n]); werr != nil {
						// Primary conn failed write — evict it immediately
						// and pick the next active one.
						pool.remove(stickyConn)
						_ = stickyConn.Close()
						stickyConn = pool.pick()
						if stickyConn != nil {
							_, _ = stickyConn.Write(buf[:n])
						}
					}
				}
			}
		}(pc, ctx)

		return nil
	}

	// Legacy TCP / KCP+smux listener loop (for VLESS etc.)
	listenAddr := fmt.Sprintf("127.0.0.1:%d", cfg.LocalPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		cancel()
		clientRunning = false
		return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	tcpAddr, _ := listener.Addr().(*net.TCPAddr)
	activeLocalPort = tcpAddr.Port
	activeListener = listener
	log.Printf("[VK TURN Client] Listening TCP on 127.0.0.1:%d for traffic to %s (streams: %d)", activeLocalPort, peerAddr, cfg.Streams)

	pool := &sessionPool{}
	activePool = pool

	// Staggered session maintenance goroutines
	for i := 0; i < cfg.Streams; i++ {
		activeWg.Add(1)
		go func(id int) {
			defer activeWg.Done()
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(id) * 350 * time.Millisecond):
			}
			maintainSession(ctx, &cfg, peerUDP, id+1, pool)
		}(i)
	}

	// Local listener loop
	go func(l net.Listener, c context.Context) {
		defer func() {
			_ = l.Close()
			clientMu.Lock()
			if activeListener == l {
				clientRunning = false
				clientCancel = nil
				activeListener = nil
				activeLocalPort = 0
				activePool = nil
			}
			clientMu.Unlock()
		}()

		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}

			sess := pool.pick()
			if sess == nil || sess.IsClosed() {
				log.Printf("[VK TURN Client] No active VK TURN sessions available, rejecting connection")
				_ = conn.Close()
				continue
			}

			go func(c net.Conn, s *smux.Session) {
				defer c.Close()
				stream, err := s.OpenStream()
				if err != nil {
					log.Printf("[VK TURN Client] smux open stream error: %v", err)
					return
				}
				defer stream.Close()
				pipe(ctx, c, stream)
			}(conn, sess)
		}
	}(listener, ctx)

	return nil
}

// StopVkTurnClient stops the running VK TURN client and unblocks immediately.
func StopVkTurnClient() error {
	clientMu.Lock()
	stopVkTurnClientLocked()
	clientMu.Unlock()

	// Wait up to 500ms for goroutines to clean up, but never freeze caller/UI thread
	done := make(chan struct{})
	go func() {
		activeWg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		log.Printf("[VK TURN Client] Stop: background cleanup completing asynchronously")
	}
	return nil
}

// IsVkTurnClientRunning returns true if the client is active.
func IsVkTurnClientRunning() bool {
	clientMu.Lock()
	defer clientMu.Unlock()
	return clientRunning
}

// GetVkTurnLocalPort returns the active local listening port.
func GetVkTurnLocalPort() int {
	clientMu.Lock()
	defer clientMu.Unlock()
	return activeLocalPort
}

// GetVkTurnActiveStreams returns the number of currently active VK TURN sessions.
func GetVkTurnActiveStreams() int {
	clientMu.Lock()
	defer clientMu.Unlock()
	if activeDtlsPool != nil {
		return activeDtlsPool.count()
	}
	if activePool != nil {
		return activePool.count()
	}
	return 0
}
