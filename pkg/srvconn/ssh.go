package srvconn

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/jumpserver/koko/pkg/logger"
)

const sshClientVersion = "SSH-2.0-CSSH-1.0-JumpServer"

type SSHClientOption func(conf *SSHClientOptions)

type SSHClientOptions struct {
	Host         string
	Port         string
	Username     string
	Password     string
	PrivateKey   string
	Passphrase   string
	Timeout      int
	keyboardAuth gossh.KeyboardInteractiveChallenge
	PrivateAuth  gossh.Signer

	proxySSHClientOptions []SSHClientOptions
}

type sshClientAttempt struct {
	label  string
	config *gossh.ClientConfig
}

func (cfg *SSHClientOptions) AuthMethods() []gossh.AuthMethod {
	authMethods := make([]gossh.AuthMethod, 0, 3)

	if signer := cfg.parsePrivateKeySigner(); signer != nil {
		authMethods = append(authMethods, gossh.PublicKeys(signer))
	}
	if cfg.PrivateAuth != nil {
		authMethods = append(authMethods, gossh.PublicKeys(cfg.PrivateAuth))
	}
	if cfg.Password != "" {
		authMethods = append(authMethods, gossh.Password(cfg.Password))
	}
	if cfg.keyboardAuth != nil {
		authMethods = append(authMethods, gossh.KeyboardInteractive(cfg.keyboardAuth))
	}
	if cfg.keyboardAuth == nil && cfg.Password != "" {
		cfg.keyboardAuth = func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
			if len(questions) == 0 {
				return []string{}, nil
			}
			return []string{cfg.Password}, nil
		}
		authMethods = append(authMethods, gossh.KeyboardInteractive(cfg.keyboardAuth))
	}

	return authMethods
}

func (cfg *SSHClientOptions) GMAuthMethods() []gossh.AuthMethod {
	authMethods := make([]gossh.AuthMethod, 0, 3)

	if signer := cfg.parsePrivateKeySigner(); signer != nil && signer.PublicKey().Type() == gossh.KeyAlgoSM2 {
		authMethods = append(authMethods, gossh.GMPublicKeys(signer))
	}
	if cfg.PrivateAuth != nil && cfg.PrivateAuth.PublicKey().Type() == gossh.KeyAlgoSM2 {
		authMethods = append(authMethods, gossh.GMPublicKeys(cfg.PrivateAuth))
	}
	if cfg.Password != "" {
		authMethods = append(authMethods, gossh.GMPassword(cfg.Password))
	}

	return authMethods
}

func (cfg *SSHClientOptions) parsePrivateKeySigner() gossh.Signer {
	if cfg.PrivateKey == "" {
		return nil
	}

	var (
		signer gossh.Signer
		err    error
	)
	if cfg.Passphrase != "" {
		// 先使用 passphrase 解析 PrivateKey
		if signer, err = gossh.ParsePrivateKeyWithPassphrase([]byte(cfg.PrivateKey),
			[]byte(cfg.Passphrase)); err == nil {
			return signer
		}
	}

	// 1. 如果之前使用解析失败，则去掉 passphrase，则尝试直接解析 PrivateKey 防止错误的passphrase
	// 2. 如果没有 Passphrase 则直接解析 PrivateKey
	if signer, err = gossh.ParsePrivateKey([]byte(cfg.PrivateKey)); err == nil {
		return signer
	}

	return nil
}

func (cfg *SSHClientOptions) clientConfig(auth []gossh.AuthMethod) *gossh.ClientConfig {
	return &gossh.ClientConfig{
		User:              cfg.Username,
		Auth:              auth,
		ClientVersion:     sshClientVersion,
		Timeout:           time.Duration(cfg.Timeout) * time.Second,
		HostKeyCallback:   gossh.InsecureIgnoreHostKey(),
		Config:            createSSHConfig(),
		HostKeyAlgorithms: allHostKeyAlgorithms(),
	}
}

func (cfg *SSHClientOptions) clientConfigAttempts() []sshClientAttempt {
	attempts := make([]sshClientAttempt, 0, 2)
	if gmAuth := cfg.GMAuthMethods(); len(gmAuth) > 0 {
		attempts = append(attempts, sshClientAttempt{
			label:  "gm",
			config: cfg.clientConfig(gmAuth),
		})
	}

	classicAuth := cfg.AuthMethods()
	if len(classicAuth) > 0 || len(attempts) == 0 {
		attempts = append(attempts, sshClientAttempt{
			label:  "classic",
			config: cfg.clientConfig(classicAuth),
		})
	}
	return attempts
}

func SSHClientUsername(username string) SSHClientOption {
	return func(args *SSHClientOptions) {
		args.Username = username
	}
}

func SSHClientPassword(password string) SSHClientOption {
	return func(args *SSHClientOptions) {
		args.Password = password
	}
}

func SSHClientPrivateKey(privateKey string) SSHClientOption {
	return func(args *SSHClientOptions) {
		args.PrivateKey = privateKey
	}
}

func SSHClientPassphrase(passphrase string) SSHClientOption {
	return func(args *SSHClientOptions) {
		args.Passphrase = passphrase
	}
}

func SSHClientHost(host string) SSHClientOption {
	return func(args *SSHClientOptions) {
		args.Host = host
	}
}

func SSHClientPort(port int) SSHClientOption {
	return func(args *SSHClientOptions) {
		args.Port = strconv.Itoa(port)
	}
}

func SSHClientTimeout(timeout int) SSHClientOption {
	return func(args *SSHClientOptions) {
		args.Timeout = timeout
	}
}

func SSHClientPrivateAuth(privateAuth gossh.Signer) SSHClientOption {
	return func(args *SSHClientOptions) {
		args.PrivateAuth = privateAuth
	}
}

func SSHClientProxyClient(proxyArgs ...SSHClientOptions) SSHClientOption {
	return func(args *SSHClientOptions) {
		args.proxySSHClientOptions = proxyArgs
	}
}

func SSHClientKeyboardAuth(keyboardAuth gossh.KeyboardInteractiveChallenge) SSHClientOption {
	return func(conf *SSHClientOptions) {
		conf.keyboardAuth = keyboardAuth
	}
}

func NewSSHClient(opts ...SSHClientOption) (*SSHClient, error) {
	cfg := &SSHClientOptions{
		Host: "127.0.0.1",
		Port: "22",
	}
	for _, setter := range opts {
		setter(cfg)
	}
	return NewSSHClientWithCfg(cfg)
}

var (
	ErrNoAvailable = errors.New("no available gateway")
	ErrGatewayDial = errors.New("gateway dial addr failed")
	ErrSSHClient   = errors.New("new ssh client failed")
)

func getAvailableProxyClient(cfgs ...SSHClientOptions) (*SSHClient, error) {
	for i := range cfgs {
		if proxyClient, err := NewSSHClientWithCfg(&cfgs[i]); err == nil {
			return proxyClient, nil
		}
	}
	return nil, ErrNoAvailable
}

func NewSSHClientWithCfg(cfg *SSHClientOptions) (*SSHClient, error) {
	destAddr := net.JoinHostPort(cfg.Host, cfg.Port)
	attempts := cfg.clientConfigAttempts()
	if len(cfg.proxySSHClientOptions) > 0 {
		proxyClient, err := getAvailableProxyClient(cfg.proxySSHClientOptions...)
		if err != nil {
			logger.Errorf("Get gateway client err: %s", err)
			return nil, err
		}
		logger.Infof("Get gateway client(%s) success ", proxyClient)
		gosshClient, err := dialProxySSHWithFallback(proxyClient, destAddr, attempts)
		if err != nil {
			_ = proxyClient.Close()
			return nil, err
		}
		return &SSHClient{Cfg: cfg, Client: gosshClient,
			traceSessionMap: make(map[*gossh.Session]time.Time),
			ProxyClient:     proxyClient}, nil
	}

	gosshClient, err := dialDirectSSHWithFallback(destAddr, time.Duration(cfg.Timeout)*time.Second, attempts)
	if err != nil {
		return nil, err
	}
	return &SSHClient{Client: gosshClient, Cfg: cfg,
		traceSessionMap: make(map[*gossh.Session]time.Time)}, nil
}

func dialDirectSSHWithFallback(destAddr string, timeout time.Duration, attempts []sshClientAttempt) (*gossh.Client, error) {
	var lastErr error
	for i, attempt := range attempts {
		conn, err := net.DialTimeout("tcp", destAddr, timeout)
		if err != nil {
			return nil, err
		}

		clientConn, chans, reqs, err := gossh.NewClientConn(conn, destAddr, attempt.config)
		if err == nil {
			if i > 0 {
				logger.Infof("SSH dial %s fallback succeeded with %s mode", destAddr, attempt.label)
			}
			return gossh.NewClient(clientConn, chans, reqs), nil
		}

		lastErr = err
		_ = conn.Close()
		logSSHAttemptFallback(destAddr, attempts, i, err)
	}
	return nil, fmt.Errorf("%w: %s", ErrSSHClient, lastErr)
}

func dialProxySSHWithFallback(proxyClient *SSHClient, destAddr string, attempts []sshClientAttempt) (*gossh.Client, error) {
	var lastErr error
	for i, attempt := range attempts {
		destConn, err := proxyClient.Dial("tcp", destAddr)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrGatewayDial, err)
		}

		clientConn, chans, reqs, err := gossh.NewClientConn(destConn, destAddr, attempt.config)
		if err == nil {
			if i > 0 {
				logger.Infof("SSH dial %s via proxy fallback succeeded with %s mode", destAddr, attempt.label)
			}
			return gossh.NewClient(clientConn, chans, reqs), nil
		}

		lastErr = err
		_ = destConn.Close()
		logSSHAttemptFallback(destAddr, attempts, i, err)
	}
	return nil, fmt.Errorf("%w: %s", ErrSSHClient, lastErr)
}

func logSSHAttemptFallback(destAddr string, attempts []sshClientAttempt, idx int, err error) {
	if idx+1 >= len(attempts) {
		return
	}
	logger.Warnf("SSH dial %s with %s mode failed: %v; fallback to %s mode",
		destAddr, attempts[idx].label, err, attempts[idx+1].label)
}

type SSHClient struct {
	*gossh.Client
	Cfg         *SSHClientOptions
	ProxyClient *SSHClient

	sync.Mutex

	traceSessionMap map[*gossh.Session]time.Time

	refCount int32
	_selfRef int32

	KeyId string
}

func (s *SSHClient) increaseSelfRef() {
	s._selfRef++
}

func (s *SSHClient) decreaseSelfRef() {
	s._selfRef--
}

func (s *SSHClient) selfRef() int32 {
	return s._selfRef
}

func (s *SSHClient) String() string {
	return fmt.Sprintf("%s@%s:%s", s.Cfg.Username,
		s.Cfg.Host, s.Cfg.Port)
}

func (s *SSHClient) Close() error {
	if s.ProxyClient != nil {
		_ = s.ProxyClient.Close()
		logger.Infof("SSHClient(%s) proxy (%s) close", s, s.ProxyClient)
	}
	err := s.Client.Close()
	logger.Infof("SSHClient(%s) close", s)
	return err
}

func (s *SSHClient) RefCount() int32 {
	return atomic.LoadInt32(&s.refCount)
}

func (s *SSHClient) AcquireSession() (*gossh.Session, error) {
	atomic.AddInt32(&s.refCount, 1)
	sess, err := s.Client.NewSession()
	if err != nil {
		atomic.AddInt32(&s.refCount, -1)
		return nil, err
	}
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	s.traceSessionMap[sess] = time.Now()
	logger.Infof("SSHClient(%s) session add one ", s)
	return sess, nil
}

func (s *SSHClient) ReleaseSession(sess *gossh.Session) {
	atomic.AddInt32(&s.refCount, -1)
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	delete(s.traceSessionMap, sess)
	logger.Infof("SSHClient(%s) release one session remain %d", s, len(s.traceSessionMap))
}

func createSSHConfig() gossh.Config {
	var cfg gossh.Config
	cfg.SetDefaults()
	algos := gossh.SupportedAlgorithms()
	insecureAlgos := gossh.InsecureAlgorithms()

	// 国密算法优先
	ciphers := make([]string, 0, len(algos.Ciphers)+len(insecureAlgos.Ciphers)+4)
	ciphers = append(ciphers, gossh.CipherSM4GCM, gossh.CipherSM4CTR, gossh.CipherSM4CBC)
	ciphers = append(ciphers, gossh.CipherAES128CTR)
	ciphers = append(ciphers, insecureAlgos.Ciphers...)
	ciphers = append(ciphers, algos.Ciphers...)

	keyExchanges := make([]string, 0, len(algos.KeyExchanges)+len(insecureAlgos.KeyExchanges)+2)
	keyExchanges = append(keyExchanges, gossh.KeyExchangeSM2SM3)
	keyExchanges = append(keyExchanges, insecureAlgos.KeyExchanges...)
	keyExchanges = append(keyExchanges, algos.KeyExchanges...)

	macs := make([]string, 0, len(cfg.MACs)+2)
	macs = append(macs, gossh.HMACSM3, gossh.CBCMAC)
	macs = append(macs, cfg.MACs...)

	cfg.Ciphers = ciphers
	cfg.KeyExchanges = keyExchanges
	cfg.MACs = macs
	return cfg
}

func allHostKeyAlgorithms() []string {
	supportedAlgos := gossh.SupportedAlgorithms()
	insecureAlgos := gossh.InsecureAlgorithms()
	hostKeyAlgos := make([]string, 0, len(supportedAlgos.HostKeys)+len(insecureAlgos.HostKeys)+1)
	// 国密算法优先
	hostKeyAlgos = append(hostKeyAlgos, gossh.KeyAlgoSM2)
	hostKeyAlgos = append(hostKeyAlgos, gossh.KeyAlgoED25519)
	hostKeyAlgos = append(hostKeyAlgos, supportedAlgos.HostKeys...)
	hostKeyAlgos = append(hostKeyAlgos, insecureAlgos.HostKeys...)
	return hostKeyAlgos
}
