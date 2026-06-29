// cmd/gmssh — 国密 SSH 客户端测试工具
//
// 用于验证 KoKo 的 GM/T 0129-2023 国密 SSH 实现，包括：
//   - SM2-SM3 密钥交换
//   - SM4-CTR/GCM/CBC 对称加密
//   - HMAC-SM3 / CBC-MAC 消息认证
//   - GM/T 0129 密码认证 & SM2 公钥认证
//
// 用法:
//
//	go build -o gmssh ./cmd/gmssh/
//	./gmssh -keygen                            # 生成 SM2 密钥对（默认保存到 ~/.ssh/id_sm2）
//	./gmssh -keygen -f /path/to/key            # 指定密钥输出路径
//	./gmssh -keygen -C "user@host"             # 添加注释
//	./gmssh -keygen -passphrase "secret"       # 使用口令加密私钥
//	./gmssh -host 127.0.0.1 -port 2222 -user admin -password <pwd>
//	./gmssh -host 127.0.0.1 -port 2222 -user admin -key ~/.ssh/id_sm2
//	./gmssh -v    # debug1 — 类似 ssh -v
//	./gmssh -vv   # debug2 — 类似 ssh -vv
//	./gmssh -vvv  # debug3 — 类似 ssh -vvv
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	ssh "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// ANSI color helpers for log output
const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorRed    = "\033[31m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"

	sshClientVersion = "CSSH-1.0-JumpServer"
)

var verbosity int

func logStep(step int, msg string) {
	fmt.Printf("%s[Step %d]%s %s%s%s\n", colorCyan, step, colorReset, colorBold, msg, colorReset)
}

func logOK(msg string) {
	fmt.Printf("  %s✓%s %s\n", colorGreen, colorReset, msg)
}

func logInfo(msg string) {
	fmt.Printf("  %s→%s %s\n", colorYellow, colorReset, msg)
}

func logErr(msg string) {
	fmt.Printf("  %s✗%s %s\n", colorRed, colorReset, msg)
}

// It prints debug messages with level prefix, like OpenSSH's ssh -vvv.
func sshDebugLogger(level int, format string, args ...any) {
	if level > verbosity {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%sdebug%d: %s%s\n", colorDim, level, msg, colorReset)
}

func main() {
	// --- CLI flags ---
	doKeygen := flag.Bool("keygen", false, "Generate a new SM2 key pair (GM/T 0129-2023)")
	keygenFile := flag.String("f", "", "Output file for generated key pair (default: ~/.ssh/id_sm2)")
	keygenComment := flag.String("C", "", "Comment to embed in the generated public key")
	keygenPassphrase := flag.String("passphrase", "", "Passphrase to encrypt the private key (empty = no encryption)")

	host := flag.String("host", "127.0.0.1", "SSH server host")
	port := flag.String("port", "2222", "SSH server port")
	user := flag.String("user", "admin", "SSH username")
	password := flag.String("password", "", "Password for GM/T 0129 password auth")
	keyFile := flag.String("key", "", "Path to SM2 private key file (default: ~/.ssh/id_sm2)")
	kexAlgo := flag.String("kex", "sm2-sm3", "Key exchange algorithm")
	cipherAlgo := flag.String("cipher", "sm4-ctr", "Cipher algorithm (sm4-ctr, sm4-gcm, sm4-cbc)")
	macAlgo := flag.String("mac", "hmac-sm3", "MAC algorithm (hmac-sm3, cbc-mac)")
	hostKeyAlgo := flag.String("hostkey", "sm2", "Host key algorithm")
	hostCertCA := flag.String("hostcert-ca", "", "Path to PEM root certificate(s) for GM host certificate verification")
	timeout := flag.Duration("timeout", 30*time.Second, "Connection timeout")

	// Verbose flags: -v, -vv, -vvv (like ssh)
	v1 := flag.Bool("v", false, "Verbose mode (debug1, like ssh -v)")
	v2 := flag.Bool("vv", false, "More verbose (debug2, like ssh -vv)")
	v3 := flag.Bool("vvv", false, "Maximum verbose (debug3, like ssh -vvv)")

	flag.Parse()

	// Determine verbosity level
	switch {
	case *v3:
		verbosity = 3
	case *v2:
		verbosity = 2
	case *v1:
		verbosity = 1
	}

	if verbosity > 0 {
		ssh.SetDebugLogger(sshDebugLogger)
	}

	// --- keygen mode ---
	if *doKeygen {
		if err := runKeygen(*keygenFile, *keygenComment, *keygenPassphrase); err != nil {
			logErr(err.Error())
			os.Exit(1)
		}
		return
	}

	// Default key path: ~/.ssh/id_sm2
	if *keyFile == "" && *password == "" {
		if home, err := os.UserHomeDir(); err == nil {
			defaultKey := filepath.Join(home, ".ssh", "id_sm2")
			if _, err := os.Stat(defaultKey); err == nil {
				*keyFile = defaultKey
			}
		}
	}

	if *password == "" && *keyFile == "" {
		fmt.Fprintln(os.Stderr, "Error: must specify -password or -key (or use -keygen to generate a key pair)")
		flag.Usage()
		os.Exit(1)
	}

	addr := net.JoinHostPort(*host, *port)

	fmt.Printf("\n%s╔══════════════════════════════════╗%s\n", colorCyan, colorReset)
	fmt.Printf("%s║       GM SSH Client Tool         ║%s\n", colorCyan, colorReset)
	fmt.Printf("%s╚══════════════════════════════════╝%s\n\n", colorCyan, colorReset)

	if verbosity > 0 {
		logInfo(fmt.Sprintf("Debug verbosity: level %d (-"+strings.Repeat("v", verbosity)+")", verbosity))
	}

	// --- Step 1: Build auth methods ---
	step := 1
	logStep(step, "Preparing authentication method")

	var (
		gmAuthMethods []ssh.AuthMethod
		authDesc      []string
	)

	if *keyFile != "" {
		keyData, err := os.ReadFile(*keyFile)
		if err != nil {
			log.Fatalf("Failed to read key file %s: %v", *keyFile, err)
		}
		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			log.Fatalf("Failed to parse SM2 private key: %v", err)
		}
		if signer.PublicKey().Type() != ssh.KeyAlgoSM2 {
			log.Fatalf("SM2 private key required for GM/T 0129 public key auth, got %s", signer.PublicKey().Type())
		}
		logOK(fmt.Sprintf("Loaded SM2 private key from: %s", *keyFile))
		logInfo(fmt.Sprintf("Public key fingerprint: %s", fingerprint(signer.PublicKey())))
		gmAuthMethods = append(gmAuthMethods, ssh.GMPublicKeys(signer))
		authDesc = append(authDesc, fmt.Sprintf("GM/T 0129 PublicKey (SM2, file: %s)", *keyFile))
	}

	if *password != "" {
		gmAuthMethods = append(gmAuthMethods, ssh.GMPassword(*password))
		authDesc = append(authDesc, "GM/T 0129 Password (SM3 challenge-response)")
		logOK("Configured GM/T 0129 password authentication")
		logInfo("Password mode: strict (no plaintext password field)")
	}

	if len(gmAuthMethods) == 0 {
		logErr("No usable authentication method after config parsing")
		os.Exit(1)
	}

	if len(authDesc) > 0 {
		logInfo(fmt.Sprintf("Auth strategy: %s", strings.Join(authDesc, " + ")))
	}
	logInfo("Negotiation mode: GM/T 0129 only")

	// --- Step 2: Configure algorithms ---
	step++
	logStep(step, "Configuring cryptographic algorithms")
	kexAlgos, err := buildKexAlgorithms(*kexAlgo)
	if err != nil {
		logErr(err.Error())
		os.Exit(1)
	}
	cipherAlgos, err := buildCipherAlgorithms(*cipherAlgo)
	if err != nil {
		logErr(err.Error())
		os.Exit(1)
	}
	macAlgos, err := buildMACAlgorithms(*macAlgo)
	if err != nil {
		logErr(err.Error())
		os.Exit(1)
	}
	hostKeyAlgos, err := buildHostKeyAlgorithms(*hostKeyAlgo)
	if err != nil {
		logErr(err.Error())
		os.Exit(1)
	}
	logInfo(fmt.Sprintf("KEX:     %s", strings.Join(kexAlgos, ", ")))
	logInfo(fmt.Sprintf("Cipher:  %s", strings.Join(cipherAlgos, ", ")))
	logInfo(fmt.Sprintf("MAC:     %s", strings.Join(macAlgos, ", ")))
	logInfo(fmt.Sprintf("HostKey: %s", strings.Join(hostKeyAlgos, ", ")))
	if *hostCertCA != "" {
		logInfo(fmt.Sprintf("HostCert CA: %s", *hostCertCA))
	}

	var gmHostCertificateCallback ssh.GMHostCertificateCallback
	if *hostCertCA != "" {
		rootPEM, err := os.ReadFile(*hostCertCA)
		if err != nil {
			log.Fatalf("Failed to read GM host certificate root file %s: %v", *hostCertCA, err)
		}
		roots := smx509.NewCertPool()
		if !roots.AppendCertsFromPEM(rootPEM) {
			log.Fatalf("Failed to parse any certificate from %s", *hostCertCA)
		}
		logOK(fmt.Sprintf("Loaded GM host certificate root(s) from: %s", *hostCertCA))

		gmHostCertificateCallback = func(hostname string, remote net.Addr, signingCert, encryptionCert *smx509.Certificate) error {
			opts := smx509.VerifyOptions{
				Roots:       roots,
				CurrentTime: time.Now(),
				KeyUsages:   []smx509.ExtKeyUsage{smx509.ExtKeyUsageAny},
			}
			if _, err := signingCert.Verify(opts); err != nil {
				return fmt.Errorf("verify GM signing certificate: %w", err)
			}
			logOK(fmt.Sprintf("GM signing certificate verified: %s", signingCert.Subject.CommonName))

			if encryptionCert != nil {
				if _, err := encryptionCert.Verify(opts); err != nil {
					return fmt.Errorf("verify GM encryption certificate: %w", err)
				}
				logOK(fmt.Sprintf("GM encryption certificate verified: %s", encryptionCert.Subject.CommonName))
			}
			return nil
		}
	}

	hostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if key.Type() != ssh.KeyAlgoSM2 {
			return fmt.Errorf("non-SM2 host key rejected: %s", key.Type())
		}
		logOK(fmt.Sprintf("Host key type:        %s", key.Type()))
		logOK(fmt.Sprintf("Host key fingerprint: %s", fingerprint(key)))
		return nil // Accept all host keys for testing
	}
	bannerCallback := func(message string) error {
		if message != "" {
			logInfo(fmt.Sprintf("Server banner: %s", strings.TrimSpace(message)))
		}
		return nil
	}

	clientConfig := buildClientConfig(*user, gmAuthMethods, *timeout, kexAlgos, cipherAlgos, macAlgos, hostKeyAlgos,
		gmHostCertificateCallback, hostKeyCallback, bannerCallback)
	logOK("ClientConfig built successfully")

	// --- Step 3: TCP connect + SSH handshake ---
	step++
	logStep(step, fmt.Sprintf("Connecting to %s", addr))
	logInfo(fmt.Sprintf("User: %s", *user))
	sshConn, chans, reqs, err := dialClientConn(addr, *timeout, clientConfig)
	if err != nil {
		logErr(fmt.Sprintf("SSH handshake failed: %v", err))
		os.Exit(1)
	}
	defer sshConn.Close()

	logOK("Negotiation path: GM")
	logOK(fmt.Sprintf("Session ID: %s", hex.EncodeToString(sshConn.SessionID())))
	logOK(fmt.Sprintf("Server version: %s", string(sshConn.ServerVersion())))
	logOK(fmt.Sprintf("Client version: %s", string(sshConn.ClientVersion())))

	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	// --- Step 4: Interactive shell ---
	step++
	logStep(step, "Opening interactive shell session")
	if err := runShell(client); err != nil {
		logErr(fmt.Sprintf("Shell session error: %v", err))
		os.Exit(1)
	}
}

func buildClientConfig(
	user string,
	authMethods []ssh.AuthMethod,
	timeout time.Duration,
	kexAlgos, cipherAlgos, macAlgos, hostKeyAlgos []string,
	gmHostCertificateCallback ssh.GMHostCertificateCallback,
	hostKeyCallback ssh.HostKeyCallback,
	bannerCallback ssh.BannerCallback,
) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:          user,
		Auth:          authMethods,
		ClientVersion: sshClientVersion,
		Config: ssh.Config{
			KeyExchanges:             kexAlgos,
			Ciphers:                  cipherAlgos,
			MACs:                     macAlgos,
			OmitOpenSSHKexExtensions: true,
		},
		HostKeyAlgorithms:         hostKeyAlgos,
		GMHostCertificateCallback: gmHostCertificateCallback,
		HostKeyCallback:           hostKeyCallback,
		Timeout:                   timeout,
		BannerCallback:            bannerCallback,
	}
}

func dialClientConn(addr string, timeout time.Duration, config *ssh.ClientConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	connectStart := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, nil, nil, err
	}
	logOK(fmt.Sprintf("TCP connected in %v", time.Since(connectStart).Round(time.Millisecond)))

	handshakeStart := time.Now()
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	logOK(fmt.Sprintf("SSH handshake completed in %v", time.Since(handshakeStart).Round(time.Millisecond)))
	return sshConn, chans, reqs, nil
}

func buildKexAlgorithms(preferred string) ([]string, error) {
	return buildGMAlgorithms(preferred, []string{ssh.KeyExchangeSM2SM3}, "key exchange")
}

func buildCipherAlgorithms(preferred string) ([]string, error) {
	return buildGMAlgorithms(preferred, []string{ssh.CipherSM4GCM, ssh.CipherSM4CTR, ssh.CipherSM4CBC}, "cipher")
}

func buildMACAlgorithms(preferred string) ([]string, error) {
	return buildGMAlgorithms(preferred, []string{ssh.HMACSM3, ssh.CBCMAC}, "MAC")
}

func buildHostKeyAlgorithms(preferred string) ([]string, error) {
	return buildGMAlgorithms(preferred, []string{ssh.KeyAlgoSM2}, "host key")
}

func buildGMAlgorithms(preferred string, allowed []string, label string) ([]string, error) {
	if preferred != "" && !containsString(allowed, preferred) {
		return nil, fmt.Errorf("unsupported non-GM %s algorithm %q; allowed: %s", label, preferred, strings.Join(allowed, ", "))
	}
	return appendUniqueStrings(nil, append([]string{preferred}, allowed...)...), nil
}

func appendUniqueStrings(dst []string, values ...string) []string {
	for _, value := range values {
		if value == "" || containsString(dst, value) {
			continue
		}
		dst = append(dst, value)
	}
	return dst
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// runKeygen generates an SM2 key pair and writes them to disk in OpenSSH format.
// privPath: private key file path; public key is written to privPath+".pub".
// comment is embedded in the public key line (like ssh-keygen -C).
// passphrase encrypts the private key when non-empty.
func runKeygen(privPath, comment, passphrase string) error {
	fmt.Printf("\n%s╔══════════════════════════════════╗%s\n", colorCyan, colorReset)
	fmt.Printf("%s║    GM SSH Key Generator (SM2)    ║%s\n", colorCyan, colorReset)
	fmt.Printf("%s╚══════════════════════════════════╝%s\n\n", colorCyan, colorReset)

	// Default output path
	if privPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot determine home directory: %w", err)
		}
		privPath = filepath.Join(home, ".ssh", "id_sm2")
	}
	pubPath := privPath + ".pub"

	// Refuse to overwrite existing files
	for _, p := range []string{privPath, pubPath} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("file already exists: %s (remove it first or use -f to specify a different path)", p)
		}
	}

	// Ensure parent directory exists with safe permissions
	if err := os.MkdirAll(filepath.Dir(privPath), 0700); err != nil {
		return fmt.Errorf("cannot create directory: %w", err)
	}

	logStep(1, "Generating SM2 key pair (GM/T 0129-2023)")
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("SM2 key generation failed: %w", err)
	}
	logOK("SM2 key pair generated")

	// Marshal private key in OpenSSH format
	logStep(2, "Encoding private key (OpenSSH PEM)")
	var privPEMBlock *pem.Block
	if passphrase != "" {
		privPEMBlock, err = ssh.MarshalPrivateKeyWithPassphrase(privKey, comment, []byte(passphrase))
		logInfo("Private key will be encrypted with passphrase")
	} else {
		privPEMBlock, err = ssh.MarshalPrivateKey(privKey, comment)
		logInfo("Private key will NOT be encrypted (no passphrase)")
	}
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := os.WriteFile(privPath, pem.EncodeToMemory(privPEMBlock), 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}
	logOK(fmt.Sprintf("Private key saved: %s", privPath))

	// Marshal public key in OpenSSH authorized_keys format
	logStep(3, "Encoding public key (OpenSSH authorized_keys)")
	pubKey, err := ssh.NewPublicKey(&privKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to create SSH public key: %w", err)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey)))
	if comment != "" {
		pubLine += " " + comment
	}
	if err := os.WriteFile(pubPath, []byte(pubLine+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}
	logOK(fmt.Sprintf("Public key saved:  %s", pubPath))

	fmt.Println()
	logInfo("Key type:    SM2 (GM/T 0129-2023)")
	logInfo(fmt.Sprintf("Fingerprint: %s", fingerprint(pubKey)))
	if comment != "" {
		logInfo(fmt.Sprintf("Comment:     %s", comment))
	}
	fmt.Printf("\n  Append public key to server's authorized_keys:\n")
	fmt.Printf("  cat %s >> ~/.ssh/authorized_keys\n\n", pubPath)
	return nil
}

// runShell starts an interactive shell session.
func runShell(client *ssh.Client) error {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	// Set up terminal raw mode
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		oldState, err := term.MakeRaw(fd)
		if err != nil {
			return fmt.Errorf("terminal raw mode: %w", err)
		}
		defer term.Restore(fd, oldState)

		w, h, _ := term.GetSize(fd)
		if err := session.RequestPty("xterm-256color", h, w, ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}); err != nil {
			return fmt.Errorf("request pty: %w", err)
		}
	}

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	if err := session.Shell(); err != nil {
		return fmt.Errorf("start shell: %w", err)
	}
	return session.Wait()
}

// fingerprint returns a SHA256 fingerprint of a public key.
func fingerprint(key ssh.PublicKey) string {
	h := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.StdEncoding.EncodeToString(h[:])
}
