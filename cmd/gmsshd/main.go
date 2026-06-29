// cmd/gmsshd — 国密 SSH 服务器测试工具
//
// 用于验证 KoKo 的 GM/T 0129-2023 国密 SSH 实现，支持：
//   - SM2-SM3 密钥交换
//   - SM4-CTR/GCM/CBC 对称加密
//   - HMAC-SM3 / CBC-MAC 消息认证
//   - GM/T 0129 密码认证 & SM2 公钥认证
//
// 用法:
//
//	go build -o gmsshd ./cmd/gmsshd/
//	./gmsshd                                     # 默认监听 0.0.0.0:2222
//	./gmsshd -port 3333                          # 自定义端口
//	./gmsshd -user admin -password test123       # 自定义用户名/密码
//	./gmsshd -authorized-keys ~/.ssh/id_sm2.pub  # 启用 SM2 公钥认证
//	./gmsshd -v                                  # debug 模式
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	ssh "golang.org/x/crypto/ssh"
)

const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorRed    = "\033[31m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

func logOK(msg string)   { fmt.Printf("  %s✓%s %s\n", colorGreen, colorReset, msg) }
func logInfo(msg string) { fmt.Printf("  %s→%s %s\n", colorYellow, colorReset, msg) }
func logErr(msg string)  { fmt.Printf("  %s✗%s %s\n", colorRed, colorReset, msg) }
func logConn(msg string) { fmt.Printf("%s[CONN]%s %s\n", colorCyan, colorReset, msg) }
func logAuth(msg string) { fmt.Printf("%s[AUTH]%s %s\n", colorCyan, colorReset, msg) }

func main() {
	// keygen flags
	doKeygen := flag.Bool("keygen", false, "Generate a new SM2 key pair (GM/T 0129-2023)")
	keygenFile := flag.String("f", "", "Output file for generated key pair (default: ~/.ssh/id_sm2)")
	keygenComment := flag.String("C", "", "Comment to embed in the generated public key")
	keygenPassphrase := flag.String("passphrase", "", "Passphrase to encrypt the private key")

	// server flags
	host := flag.String("host", "0.0.0.0", "Listen host")
	port := flag.String("port", "2222", "Listen port")
	user := flag.String("user", "admin", "Allowed username")
	password := flag.String("password", "admin", "Allowed password (for GM/T 0129 password auth)")
	authorizedKeys := flag.String("authorized-keys", "", "Path to authorized_keys file (for SM2 public key auth)")
	hostKeyFile := flag.String("hostkey", "", "Path to SM2 host key file (persisted self-signed GM host certificates are generated alongside it)")
	shell := flag.String("shell", "", "Shell to run (default: $SHELL or /bin/sh)")
	verbose := flag.Bool("v", false, "Verbose debug output")
	flag.Parse()

	if *verbose {
		ssh.SetDebugLogger(func(level int, format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			fmt.Printf("%sdebug%d: %s%s\n", colorDim, level, msg, colorReset)
		})
	}

	// --- keygen mode ---
	if *doKeygen {
		if err := runKeygen(*keygenFile, *keygenComment, *keygenPassphrase); err != nil {
			logErr(err.Error())
			os.Exit(1)
		}
		return
	}

	fmt.Printf("\n%s╔══════════════════════════════════╗%s\n", colorCyan, colorReset)
	fmt.Printf("%s║      GM SSH Server (gmsshd)      ║%s\n", colorCyan, colorReset)
	fmt.Printf("%s╚══════════════════════════════════╝%s\n\n", colorCyan, colorReset)

	// --- Load or generate SM2 host key ---
	hostSigner, err := loadOrGenerateHostKey(*hostKeyFile)
	if err != nil {
		log.Fatalf("Host key error: %v", err)
	}
	logOK(fmt.Sprintf("Host key ready (type: %s)", hostSigner.PublicKey().Type()))

	// --- Load authorized keys ---
	var authorizedKeyMap map[string]bool
	if *authorizedKeys != "" {
		authorizedKeyMap, err = loadAuthorizedKeys(*authorizedKeys)
		if err != nil {
			log.Fatalf("Failed to load authorized keys: %v", err)
		}
		logOK(fmt.Sprintf("Loaded %d authorized public key(s)", len(authorizedKeyMap)))
	}

	// --- Configure server ---
	config := &ssh.ServerConfig{
		Config: ssh.Config{
			Ciphers:      []string{"sm4-gcm", "sm4-ctr", "sm4-cbc", "aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com"},
			KeyExchanges: []string{"sm2-sm3", "curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256"},
			MACs:         []string{"hmac-sm3", "cbc-mac", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-256"},
		},
		PublicKeyAuthAlgorithms: []string{
			ssh.KeyAlgoSM2,
			ssh.KeyAlgoED25519,
			ssh.KeyAlgoECDSA256,
			ssh.KeyAlgoRSASHA256,
			ssh.KeyAlgoRSASHA512,
		},
		MaxAuthTries:     6,
		ServerVersion:    "CSSH-1.0-JumpServer",
		PasswordCallback: makePasswordCallback(*user, *password),
	}

	if authorizedKeyMap != nil {
		config.PublicKeyCallback = makePublicKeyCallback(*user, authorizedKeyMap)
	}

	config.AddHostKey(hostSigner)

	logInfo(fmt.Sprintf("Ciphers:  %s", strings.Join(config.Config.Ciphers, ", ")))
	logInfo(fmt.Sprintf("KEX:      %s", strings.Join(config.Config.KeyExchanges, ", ")))
	logInfo(fmt.Sprintf("MACs:     %s", strings.Join(config.Config.MACs, ", ")))
	logInfo(fmt.Sprintf("Auth user: %s", *user))
	if authorizedKeyMap != nil {
		logInfo("Auth methods: GM password + SM2 public key")
	} else {
		logInfo("Auth methods: GM password only (-authorized-keys to enable pubkey)")
	}

	// --- Start listening ---
	addr := net.JoinHostPort(*host, *port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", addr, err)
	}
	fmt.Printf("\n%s▶ Listening on %s%s\n\n", colorGreen+colorBold, addr, colorReset)

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Printf("\n%sShutting down...%s\n", colorYellow, colorReset)
		listener.Close()
		os.Exit(0)
	}()

	shellCmd := *shell
	if shellCmd == "" {
		shellCmd = os.Getenv("SHELL")
		if shellCmd == "" {
			shellCmd = "/bin/sh"
		}
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logErr(fmt.Sprintf("Accept error: %v", err))
			continue
		}
		go handleConnection(conn, config, shellCmd)
	}
}

func handleConnection(conn net.Conn, config *ssh.ServerConfig, shell string) {
	remoteAddr := conn.RemoteAddr().String()
	logConn(fmt.Sprintf("New connection from %s", remoteAddr))

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		logErr(fmt.Sprintf("Handshake failed from %s: %v", remoteAddr, err))
		return
	}
	defer sshConn.Close()

	logConn(fmt.Sprintf("Authenticated: user=%s from %s", sshConn.User(), remoteAddr))
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		go handleSession(newChannel, shell, sshConn.User())
	}
	logConn(fmt.Sprintf("Disconnected: %s", remoteAddr))
}

func handleSession(newChannel ssh.NewChannel, shell, user string) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		logErr(fmt.Sprintf("Could not accept channel: %v", err))
		return
	}
	defer channel.Close()

	var cmd *exec.Cmd
	var once sync.Once
	closeCmd := func() {
		if cmd != nil && cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}

	envVars := []string{fmt.Sprintf("USER=%s", user), fmt.Sprintf("HOME=%s", os.Getenv("HOME"))}
	var ptyReq bool

	for req := range requests {
		switch req.Type {
		case "pty-req":
			ptyReq = true
			if req.WantReply {
				req.Reply(true, nil)
			}

		case "env":
			if req.WantReply {
				req.Reply(true, nil)
			}

		case "shell":
			if cmd != nil {
				if req.WantReply {
					req.Reply(false, nil)
				}
				continue
			}

			cmd = exec.Command(shell)
			cmd.Env = append(os.Environ(), envVars...)
			if ptyReq {
				cmd.Env = append(cmd.Env, "TERM=xterm-256color")
			}

			stdin, _ := cmd.StdinPipe()
			stdout, _ := cmd.StdoutPipe()
			stderr, _ := cmd.StderrPipe()

			if err := cmd.Start(); err != nil {
				logErr(fmt.Sprintf("Failed to start shell: %v", err))
				if req.WantReply {
					req.Reply(false, nil)
				}
				return
			}
			logAuth(fmt.Sprintf("Shell started for user %s (pid=%d)", user, cmd.Process.Pid))

			if req.WantReply {
				req.Reply(true, nil)
			}

			go io.Copy(stdin, channel)
			go io.Copy(channel, stdout)
			go io.Copy(channel.Stderr(), stderr)

			go func() {
				cmd.Wait()
				exitCode := 0
				if cmd.ProcessState != nil {
					exitCode = cmd.ProcessState.ExitCode()
				}
				channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{uint32(exitCode)}))
				channel.Close()
			}()

		case "exec":
			var payload struct{ Command string }
			ssh.Unmarshal(req.Payload, &payload)
			logAuth(fmt.Sprintf("Exec request: %s", payload.Command))

			cmd = exec.Command(shell, "-c", payload.Command)
			cmd.Env = append(os.Environ(), envVars...)

			stdout, _ := cmd.StdoutPipe()
			stderr, _ := cmd.StderrPipe()

			if err := cmd.Start(); err != nil {
				if req.WantReply {
					req.Reply(false, nil)
				}
				return
			}
			if req.WantReply {
				req.Reply(true, nil)
			}

			go io.Copy(channel, stdout)
			go io.Copy(channel.Stderr(), stderr)
			go func() {
				cmd.Wait()
				exitCode := 0
				if cmd.ProcessState != nil {
					exitCode = cmd.ProcessState.ExitCode()
				}
				channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{uint32(exitCode)}))
				channel.Close()
			}()

		case "window-change":
			if req.WantReply {
				req.Reply(true, nil)
			}

		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}

	once.Do(closeCmd)
}

// makePasswordCallback creates a GM/T 0129 password auth callback.
// For GM/T 0129 strict mode, the server sends a challenge+salt and the client
// responds with SM3(challenge||SM3(password||salt)).
func makePasswordCallback(allowedUser, allowedPassword string) func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if conn.User() != allowedUser {
			logAuth(fmt.Sprintf("Password auth REJECTED: unknown user %q", conn.User()))
			return nil, fmt.Errorf("unknown user %q", conn.User())
		}

		// Try GM/T 0129 challenge-response verification
		if challenge, salt, hasGM := ssh.GetGMAuthData(conn); hasGM {
			expected := ssh.GMPasswordResponse(allowedPassword, challenge, salt)
			if len(password) == len(expected) {
				match := true
				for i := range expected {
					if password[i] != expected[i] {
						match = false
						break
					}
				}
				if match {
					logAuth(fmt.Sprintf("GM/T 0129 password auth OK: user=%s", conn.User()))
					return nil, nil
				}
			}
			logAuth(fmt.Sprintf("GM/T 0129 password auth FAILED: user=%s", conn.User()))
			return nil, fmt.Errorf("GM/T 0129 password auth failed")
		}

		// Fallback: plaintext password (RFC 4252)
		if string(password) == allowedPassword {
			logAuth(fmt.Sprintf("Password auth OK: user=%s", conn.User()))
			return nil, nil
		}

		logAuth(fmt.Sprintf("Password auth REJECTED: user=%s", conn.User()))
		return nil, fmt.Errorf("password rejected for %q", conn.User())
	}
}

func makePublicKeyCallback(allowedUser string, authorizedKeys map[string]bool) func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if conn.User() != allowedUser {
			logAuth(fmt.Sprintf("Pubkey auth REJECTED: unknown user %q", conn.User()))
			return nil, fmt.Errorf("unknown user %q", conn.User())
		}

		keyStr := string(key.Marshal())
		if authorizedKeys[keyStr] {
			logAuth(fmt.Sprintf("Pubkey auth OK: user=%s key_type=%s", conn.User(), key.Type()))
			return nil, nil
		}

		logAuth(fmt.Sprintf("Pubkey auth REJECTED: user=%s key_type=%s", conn.User(), key.Type()))
		return nil, fmt.Errorf("unknown public key for %q", conn.User())
	}
}

func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, fmt.Errorf("create host key directory: %w", err)
		}

		data, err := os.ReadFile(path)
		var signer ssh.Signer
		if err == nil {
			signer, err = ssh.ParsePrivateKey(data)
			if err != nil {
				return nil, fmt.Errorf("parse host key: %w", err)
			}
			if err := ensurePersistentGMKexCertificateBundle(path, signer); err != nil {
				return nil, err
			}
			return signer, nil
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read host key: %w", err)
		}

		logInfo(fmt.Sprintf("Generating persistent SM2 host key: %s", path))
		key, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate SM2 key: %w", err)
		}
		block, err := ssh.MarshalPrivateKey(key, "")
		if err != nil {
			return nil, fmt.Errorf("marshal host key: %w", err)
		}
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
			return nil, fmt.Errorf("write host key: %w", err)
		}
		signer, err = ssh.NewSignerFromKey(key)
		if err != nil {
			return nil, err
		}
		if err := ensurePersistentGMKexCertificateBundle(path, signer); err != nil {
			return nil, err
		}
		return signer, nil
	}

	// Auto-generate SM2 host key
	logInfo("Generating ephemeral SM2 host key...")
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate SM2 key: %w", err)
	}
	logInfo("GM/T 0129 dual certificates stay ephemeral when -hostkey is empty")
	return ssh.NewSignerFromKey(key)
}

func ensurePersistentGMKexCertificateBundle(hostKeyPath string, signer ssh.Signer) error {
	signCertPath, encCertPath, encKeyPath := gmKexArtifactPaths(hostKeyPath)

	bundle, err := loadGMKexCertificateBundle(signCertPath, encCertPath, encKeyPath)
	if err == nil {
		if err := ssh.RegisterGMKexCertificateBundle(signer.PublicKey(), bundle); err == nil {
			logInfo(fmt.Sprintf("Loaded GM/T 0129 self-signed signing certificate: %s", signCertPath))
			logInfo(fmt.Sprintf("Loaded GM/T 0129 self-signed encryption certificate: %s", encCertPath))
			return nil
		}
		logInfo("Persisted GM/T 0129 certificates do not match current host key, regenerating")
	} else if !os.IsNotExist(err) {
		logInfo(fmt.Sprintf("Failed to load persisted GM/T 0129 certificates: %v", err))
	}

	bundle, err = ssh.NewSelfSignedGMKexCertificateBundle(rand.Reader, signer, "gmsshd-host")
	if err != nil {
		return fmt.Errorf("generate GM/T 0129 certificate bundle: %w", err)
	}
	if err := saveGMKexCertificateBundle(bundle, signCertPath, encCertPath, encKeyPath); err != nil {
		return err
	}
	if err := ssh.RegisterGMKexCertificateBundle(signer.PublicKey(), bundle); err != nil {
		return err
	}
	logInfo(fmt.Sprintf("Saved GM/T 0129 self-signed signing certificate: %s", signCertPath))
	logInfo(fmt.Sprintf("Saved GM/T 0129 self-signed encryption certificate: %s", encCertPath))
	logInfo(fmt.Sprintf("Saved GM/T 0129 encryption private key: %s", encKeyPath))
	return nil
}

func gmKexArtifactPaths(hostKeyPath string) (signCertPath, encCertPath, encKeyPath string) {
	return hostKeyPath + ".gm-sign-cert.pem", hostKeyPath + ".gm-enc-cert.pem", hostKeyPath + ".gm-enc-key"
}

func loadGMKexCertificateBundle(signCertPath, encCertPath, encKeyPath string) (*ssh.GMKexCertificateBundle, error) {
	signingCert, err := loadCertificatePEM(signCertPath)
	if err != nil {
		return nil, err
	}
	encryptionCert, err := loadCertificatePEM(encCertPath)
	if err != nil {
		return nil, err
	}
	encryptionKey, err := loadSM2PrivateKey(encKeyPath)
	if err != nil {
		return nil, err
	}
	return ssh.NewGMKexCertificateBundle(signingCert.Raw, encryptionCert.Raw, encryptionKey)
}

func saveGMKexCertificateBundle(bundle *ssh.GMKexCertificateBundle, signCertPath, encCertPath, encKeyPath string) error {
	if err := saveCertificatePEM(signCertPath, bundle.SigningCertificate()); err != nil {
		return err
	}
	if err := saveCertificatePEM(encCertPath, bundle.EncryptionCertificate()); err != nil {
		return err
	}
	return saveSM2PrivateKey(encKeyPath, bundle.EncryptionKey())
}

func loadCertificatePEM(path string) (*smx509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cert, err := smx509.ParseCertificatePEM(data)
	if err != nil {
		return nil, fmt.Errorf("parse certificate %s: %w", path, err)
	}
	return cert, nil
}

func saveCertificatePEM(path string, cert *smx509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate for %s is nil", path)
	}
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0644); err != nil {
		return fmt.Errorf("write certificate %s: %w", path, err)
	}
	return nil
}

func loadSM2PrivateKey(path string) (*sm2.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rawKey, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse SM2 private key %s: %w", path, err)
	}
	key, ok := rawKey.(*sm2.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key %s is %T, want *sm2.PrivateKey", path, rawKey)
	}
	return key, nil
}

func saveSM2PrivateKey(path string, key *sm2.PrivateKey) error {
	if key == nil {
		return fmt.Errorf("private key for %s is nil", path)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		return fmt.Errorf("marshal SM2 private key %s: %w", path, err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		return fmt.Errorf("write SM2 private key %s: %w", path, err)
	}
	return nil
}

func loadAuthorizedKeys(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	keys := make(map[string]bool)
	rest := data
	for len(rest) > 0 {
		var pubKey ssh.PublicKey
		pubKey, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
		if err != nil {
			break
		}
		keys[string(pubKey.Marshal())] = true
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid keys found in %s", path)
	}
	return keys, nil
}

// saveTempHostKey writes the host key to a temp file for debugging.
func saveTempHostKey(signer ssh.Signer) string {
	key := signer.(interface{ PrivateKey() interface{} }).PrivateKey()
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		return ""
	}
	f, err := os.CreateTemp("", "gmsshd-hostkey-*.pem")
	if err != nil {
		return ""
	}
	pem.Encode(f, block)
	f.Close()
	return f.Name()
}

// runKeygen generates an SM2 key pair and writes them to disk in OpenSSH format.
func runKeygen(privPath, comment, passphrase string) error {
	fmt.Printf("\n%s╔══════════════════════════════════╗%s\n", colorCyan, colorReset)
	fmt.Printf("%s║    GM SSH Key Generator (SM2)    ║%s\n", colorCyan, colorReset)
	fmt.Printf("%s╚══════════════════════════════════╝%s\n\n", colorCyan, colorReset)

	if privPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot determine home directory: %w", err)
		}
		privPath = filepath.Join(home, ".ssh", "id_sm2")
	}
	pubPath := privPath + ".pub"

	for _, p := range []string{privPath, pubPath} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("file already exists: %s (remove it first or use -f to specify a different path)", p)
		}
	}

	if err := os.MkdirAll(filepath.Dir(privPath), 0700); err != nil {
		return fmt.Errorf("cannot create directory: %w", err)
	}

	logInfo("Generating SM2 key pair (GM/T 0129-2023)...")
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("SM2 key generation failed: %w", err)
	}
	logOK("SM2 key pair generated")

	// Marshal private key
	var privPEMBlock *pem.Block
	if passphrase != "" {
		privPEMBlock, err = ssh.MarshalPrivateKeyWithPassphrase(privKey, comment, []byte(passphrase))
		logInfo("Private key encrypted with passphrase")
	} else {
		privPEMBlock, err = ssh.MarshalPrivateKey(privKey, comment)
	}
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := os.WriteFile(privPath, pem.EncodeToMemory(privPEMBlock), 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}
	logOK(fmt.Sprintf("Private key saved: %s", privPath))

	// Marshal public key
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
	fmt.Printf("\n  Append public key to authorized_keys:\n")
	fmt.Printf("  cat %s >> ~/.ssh/authorized_keys\n\n", pubPath)
	return nil
}

func fingerprint(key ssh.PublicKey) string {
	h := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.StdEncoding.EncodeToString(h[:])
}
