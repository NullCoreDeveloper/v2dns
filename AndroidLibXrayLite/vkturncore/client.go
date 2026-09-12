package vkturncore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
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
	{ClientID: "6287487", ClientSecret: "QbYic1K3lEV5kTGiqlq2"},  // VK_WEB_APP_ID
	{ClientID: "7879029", ClientSecret: "aR5NKGmm03GYrCiNKsaw"},  // VK_MVK_APP_ID
	{ClientID: "52461373", ClientSecret: "o557NLIkAErNhakXrQ7A"}, // VK_WEB_VKVIDEO_APP_ID
	{ClientID: "52649896", ClientSecret: "WStp4ihWG4l3nmXZgIbC"}, // VK_MVK_VKVIDEO_APP_ID
	{ClientID: "51781872", ClientSecret: "IjjCNl4L4Tf5QZEXIHKK"}, // VK_ID_AUTH_APP
}

type ClientConfig struct {
	Server         string `json:"server"`
	Port           int    `json:"port"`
	TargetProtocol string `json:"targetProtocol"`
	VkLink         string `json:"vkLink"`
	Streams        int    `json:"streams"`
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

// Global Client Runtime State
var (
	clientMu        sync.Mutex
	clientRunning   bool
	clientCancel    context.CancelFunc
	activeLocalPort int
	globalLockout   atomic.Int64
)

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

func fetchVkCreds(ctx context.Context, link string, customCred *VKCredentials, streamID int) (string, string, string, error) {
	if time.Now().Unix() < globalLockout.Load() {
		return "", "", "", fmt.Errorf("CAPTCHA_WAIT_REQUIRED: global lockout active")
	}

	credsList := defaultVkCredentials
	if customCred != nil && customCred.ClientID != "" && customCred.ClientSecret != "" {
		credsList = append([]VKCredentials{*customCred}, credsList...)
	}

	jar := tlsclient.NewCookieJar()
	var lastErr error

	for _, creds := range credsList {
		user, pass, addr, err := getTokenChain(ctx, link, creds, streamID, jar)
		if err == nil {
			return user, pass, addr, nil
		}
		lastErr = err
		log.Printf("[STREAM %d] [VK Auth] Creds failed (%s): %v", streamID, creds.ClientID, err)
	}

	return "", "", "", fmt.Errorf("all VK credentials failed: %w", lastErr)
}

func getTokenChain(ctx context.Context, link string, creds VKCredentials, streamID int, jar tlsclient.CookieJar) (string, string, string, error) {
	profile := getRandomProfile()
	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(15),
		tlsclient.WithClientProfile(profiles.Chrome_146),
		tlsclient.WithCookieJar(jar),
		tlsclient.WithDialer(getCustomNetDialer()),
	)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to init tls_client: %w", err)
	}

	name := generateName()
	escapedName := neturl.QueryEscape(name)

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
		return "", "", "", err
	}
	dataMap, ok := resp["data"].(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("invalid anon token response")
	}
	token1, ok := dataMap["access_token"].(string)
	if !ok {
		return "", "", "", fmt.Errorf("missing access_token")
	}

	time.Sleep(100 * time.Millisecond)

	// 2. Call preview
	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&fields=photo_200&access_token=%s", link, token1)
	_, _ = doRequest(data, "https://api.vk.ru/method/calls.getCallPreview?v=5.275&client_id="+creds.ClientID)

	time.Sleep(200 * time.Millisecond)

	// 3. Get Anonymous Token
	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s", link, escapedName, token1)
	urlAddr := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id=%s", creds.ClientID)

	var token2 string
	for attempt := 0; attempt < 3; attempt++ {
		resp, err = doRequest(data, urlAddr)
		if err != nil {
			return "", "", "", err
		}

		if errObj, hasErr := resp["error"].(map[string]interface{}); hasErr {
			captchaErr := ParseVkCaptchaError(errObj)
			if captchaErr != nil && captchaErr.IsCaptchaError() {
				successToken, solveErr := solveVkCaptcha(ctx, captchaErr, streamID, client, profile)
				if solveErr != nil {
					globalLockout.Store(time.Now().Add(60 * time.Second).Unix())
					return "", "", "", solveErr
				}
				data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%s&captcha_attempt=%s&access_token=%s",
					link, escapedName, captchaErr.CaptchaSid, neturl.QueryEscape(successToken), captchaErr.CaptchaTs, captchaErr.CaptchaAttempt, token1)
				continue
			}
			return "", "", "", fmt.Errorf("VK API error: %v", errObj)
		}

		respMap, okLoop := resp["response"].(map[string]interface{})
		if !okLoop {
			return "", "", "", fmt.Errorf("unexpected getAnonymousToken response")
		}
		token2, okLoop = respMap["token"].(string)
		if !okLoop {
			return "", "", "", fmt.Errorf("missing token2 in response")
		}
		break
	}

	time.Sleep(100 * time.Millisecond)

	// 4. OK Login
	sessionData := fmt.Sprintf(`{"version":2,"device_id":"%s","client_version":1.1,"client_type":"SDK_JS"}`, uuid.New())
	data = fmt.Sprintf("session_data=%s&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA", neturl.QueryEscape(sessionData))
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", err
	}
	token3, ok := resp["session_key"].(string)
	if !ok {
		return "", "", "", fmt.Errorf("missing session_key in response")
	}

	time.Sleep(100 * time.Millisecond)

	// 5. Join Conversation -> TURN Credentials
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&capabilities=2F7F&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, token2, token3)
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", err
	}

	tsRaw, ok := resp["turn_server"].(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("missing turn_server in response: %v", resp)
	}
	user, _ := tsRaw["username"].(string)
	pass, _ := tsRaw["credential"].(string)
	urlsRaw, ok := tsRaw["urls"].([]interface{})
	if !ok || len(urlsRaw) == 0 {
		return "", "", "", fmt.Errorf("missing urls in turn_server")
	}
	urlStr, _ := urlsRaw[0].(string)
	clean := strings.Split(urlStr, "?")[0]
	address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

	return user, pass, address, nil
}

func createSmuxSession(ctx context.Context, cfg *ClientConfig, peer *net.UDPAddr, streamID int) (*smux.Session, func(), error) {
	var cleanupFns []func()
	cleanup := func() {
		for i := len(cleanupFns) - 1; i >= 0; i-- {
			cleanupFns[i]()
		}
	}

	var customCred *VKCredentials
	if cfg.ClientId != "" && cfg.ClientPassword != "" {
		customCred = &VKCredentials{ClientID: cfg.ClientId, ClientSecret: cfg.ClientPassword}
	}

	user, pass, turnAddr, err := fetchVkCreds(ctx, cfg.VkLink, customCred, streamID)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch TURN creds: %w", err)
	}

	turnUDPAddr, err := net.ResolveUDPAddr("udp", turnAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve TURN address (%s): %w", turnAddr, err)
	}

	c, err := net.DialUDP("udp", nil, turnUDPAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial TURN UDP: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { _ = c.Close() })
	turnConn := &connectedUDPConn{c}

	var addrFamily turn.RequestedAddressFamily = turn.RequestedAddressFamilyIPv4
	if peer.IP.To4() == nil {
		addrFamily = turn.RequestedAddressFamilyIPv6
	}

	turnClient, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr:         turnAddr,
		TURNServerAddr:         turnAddr,
		Conn:                   turnConn,
		Net:                    directNet{},
		Username:               user,
		Password:               pass,
		RequestedAddressFamily: addrFamily,
		LoggerFactory:          logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("create TURN client: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { turnClient.Close() })

	if err = turnClient.Listen(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("TURN listen: %w", err)
	}

	relayConn, err := turnClient.Allocate()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("TURN allocate: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { _ = relayConn.Close() })

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
	if err = dtlsConn.HandshakeContext(handshakeCtx); err != nil {
		_ = dtlsConn.Close()
		cleanup()
		return nil, nil, fmt.Errorf("DTLS handshake: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { _ = dtlsConn.Close() })

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

func maintainSession(ctx context.Context, cfg *ClientConfig, peer *net.UDPAddr, id int, pool *sessionPool) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		sess, cleanup, err := createSmuxSession(ctx, cfg, peer, id)
		if err != nil {
			log.Printf("[STREAM %d] Setup error: %v, retrying in 3s...", id, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
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

	go func() {
		<-ctx2.Done()
		_ = c1.SetDeadline(time.Now())
		_ = c2.SetDeadline(time.Now())
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer cancel()
		_, _ = io.Copy(c1, c2)
	}()
	go func() {
		defer wg.Done()
		defer cancel()
		_, _ = io.Copy(c2, c1)
	}()
	wg.Wait()
}

// StartVkTurnClient starts the VK TURN client tunnel.
func StartVkTurnClient(configJsonBase64 string, logPath string, configDir string) error {
	clientMu.Lock()
	defer clientMu.Unlock()

	if clientRunning {
		return fmt.Errorf("VK TURN client is already running")
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
	if cfg.VkLink == "" {
		cfg.VkLink = "aD0YV1u9x_8m51L9H4fQ_6_16089" // fallback default conference link
	}
	if cfg.Streams <= 0 {
		cfg.Streams = 2
	}
	if cfg.Streams > 8 {
		cfg.Streams = 8
	}

	peerAddr := fmt.Sprintf("%s:%d", cfg.Server, cfg.Port)
	peerUDP, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve target server %s: %w", peerAddr, err)
	}

	listenAddr := fmt.Sprintf("127.0.0.1:%d", cfg.LocalPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	tcpAddr, _ := listener.Addr().(*net.TCPAddr)
	activeLocalPort = tcpAddr.Port
	log.Printf("[VK TURN Client] Listening on 127.0.0.1:%d for traffic to %s (streams: %d)", activeLocalPort, peerAddr, cfg.Streams)

	ctx, cancel := context.WithCancel(context.Background())
	clientCancel = cancel
	clientRunning = true

	pool := &sessionPool{}

	// Staggered session maintenance goroutines
	for i := 0; i < cfg.Streams; i++ {
		go func(id int) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(id) * 350 * time.Millisecond):
			}
			maintainSession(ctx, &cfg, peerUDP, id+1, pool)
		}(i)
	}

	// Local listener loop
	go func() {
		defer func() {
			_ = listener.Close()
			clientMu.Lock()
			clientRunning = false
			clientCancel = nil
			activeLocalPort = 0
			clientMu.Unlock()
		}()

		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					log.Printf("[VK TURN Client] Accept error: %v", err)
					return
				}
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
	}()

	return nil
}

// StopVkTurnClient stops the running VK TURN client.
func StopVkTurnClient() error {
	clientMu.Lock()
	defer clientMu.Unlock()

	if !clientRunning {
		return nil
	}

	if clientCancel != nil {
		clientCancel()
	}

	for i := 0; i < 40; i++ {
		if !clientRunning {
			break
		}
		time.Sleep(50 * time.Millisecond)
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
