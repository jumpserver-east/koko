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
//	./gmssh -host 127.0.0.1 -port 2222 -user admin -password <pwd>
//	./gmssh -host 127.0.0.1 -port 2222 -user admin -key ~/.ssh/sm2_key
//	./gmssh -v    # debug1 — 类似 ssh -v
//	./gmssh -vv   # debug2 — 类似 ssh -vv
//	./gmssh -vvv  # debug3 — 类似 ssh -vvv
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

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

// sshDebugLogger is the callback for ssh.SetDebugLogger.
// It prints debug messages with level prefix, like OpenSSH's ssh -vvv.
func sshDebugLogger(level int, format string, args ...interface{}) {
	if level > verbosity {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%sdebug%d: %s%s\n", colorDim, level, msg, colorReset)
}

func main() {
	// --- CLI flags ---
	host := flag.String("host", "127.0.0.1", "SSH server host")
	port := flag.String("port", "2222", "SSH server port")
	user := flag.String("user", "admin", "SSH username")
	password := flag.String("password", "", "Password for GM/T 0129 password auth")
	keyFile := flag.String("key", "", "Path to SM2 private key file (OpenSSH PEM format) for GM/T 0129 public key auth")
	kexAlgo := flag.String("kex", "sm2-sm3", "Key exchange algorithm")
	cipherAlgo := flag.String("cipher", "sm4-ctr", "Cipher algorithm (sm4-ctr, sm4-gcm, sm4-cbc)")
	macAlgo := flag.String("mac", "hmac-sm3", "MAC algorithm (hmac-sm3, cbc-mac)")
	hostKeyAlgo := flag.String("hostkey", "sm2", "Host key algorithm")
	shellMode := flag.Bool("shell", false, "Start interactive shell after auth")
	cmd := flag.String("cmd", "", "Command to execute after auth (default: whoami)")
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

	if *password == "" && *keyFile == "" {
		fmt.Fprintln(os.Stderr, "Error: must specify -password or -key")
		flag.Usage()
		os.Exit(1)
	}

	addr := net.JoinHostPort(*host, *port)

	fmt.Printf("\n%s╔══════════════════════════════════════════════════╗%s\n", colorCyan, colorReset)
	fmt.Printf("%s║    GM/T 0129-2023 SSH Client Test Tool            ║%s\n", colorCyan, colorReset)
	fmt.Printf("%s╚══════════════════════════════════════════════════╝%s\n\n", colorCyan, colorReset)

	if verbosity > 0 {
		logInfo(fmt.Sprintf("Debug verbosity: level %d (-"+strings.Repeat("v", verbosity)+")", verbosity))
	}

	// --- Step 1: Build auth methods ---
	step := 1
	logStep(step, "Preparing authentication method")

	var authMethods []ssh.AuthMethod
	authDesc := ""

	if *keyFile != "" {
		keyData, err := os.ReadFile(*keyFile)
		if err != nil {
			log.Fatalf("Failed to read key file %s: %v", *keyFile, err)
		}
		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			log.Fatalf("Failed to parse SM2 private key: %v", err)
		}
		authMethods = append(authMethods, ssh.GMPublicKeys(signer))
		authDesc = fmt.Sprintf("GM/T 0129 PublicKey (SM2, file: %s)", *keyFile)
		logOK(fmt.Sprintf("Loaded SM2 private key from: %s", *keyFile))
		logInfo(fmt.Sprintf("Public key fingerprint: %s", fingerprint(signer.PublicKey())))
	}

	if *password != "" {
		authMethods = append(authMethods, ssh.GMPassword(*password))
		if authDesc == "" {
			authDesc = "GM/T 0129 Password (SM3 challenge-response)"
		} else {
			authDesc += " + GM/T 0129 Password (fallback)"
		}
		logOK("Configured GM/T 0129 password authentication")
	}

	logInfo(fmt.Sprintf("Auth strategy: %s", authDesc))

	// --- Step 2: Configure algorithms ---
	step++
	logStep(step, "Configuring cryptographic algorithms")
	logInfo(fmt.Sprintf("KEX:     %s", *kexAlgo))
	logInfo(fmt.Sprintf("Cipher:  %s", *cipherAlgo))
	logInfo(fmt.Sprintf("MAC:     %s", *macAlgo))
	logInfo(fmt.Sprintf("HostKey: %s", *hostKeyAlgo))

	config := &ssh.ClientConfig{
		User: *user,
		Auth: authMethods,
		Config: ssh.Config{
			KeyExchanges: []string{*kexAlgo},
			Ciphers:      []string{*cipherAlgo},
			MACs:         []string{*macAlgo},
		},
		HostKeyAlgorithms: []string{*hostKeyAlgo},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			logOK(fmt.Sprintf("Host key type:        %s", key.Type()))
			logOK(fmt.Sprintf("Host key fingerprint: %s", fingerprint(key)))
			return nil // Accept all host keys for testing
		},
		Timeout: *timeout,
		BannerCallback: func(message string) error {
			if message != "" {
				logInfo(fmt.Sprintf("Server banner: %s", strings.TrimSpace(message)))
			}
			return nil
		},
	}

	logOK("ClientConfig built successfully")

	// --- Step 3: TCP connect ---
	step++
	logStep(step, fmt.Sprintf("Connecting to %s", addr))

	startTime := time.Now()
	conn, err := net.DialTimeout("tcp", addr, *timeout)
	if err != nil {
		logErr(fmt.Sprintf("TCP connection failed: %v", err))
		os.Exit(1)
	}
	logOK(fmt.Sprintf("TCP connected in %v", time.Since(startTime).Round(time.Millisecond)))

	// --- Step 4: SSH handshake (KEX + auth) ---
	step++
	logStep(step, "Starting SSH handshake (KEX negotiation + authentication)")
	logInfo(fmt.Sprintf("User: %s", *user))

	handshakeStart := time.Now()
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		logErr(fmt.Sprintf("SSH handshake failed: %v", err))
		os.Exit(1)
	}
	defer sshConn.Close()

	logOK(fmt.Sprintf("SSH handshake completed in %v", time.Since(handshakeStart).Round(time.Millisecond)))
	logOK(fmt.Sprintf("Session ID: %s", hex.EncodeToString(sshConn.SessionID())))
	logOK(fmt.Sprintf("Server version: %s", string(sshConn.ServerVersion())))
	logOK(fmt.Sprintf("Client version: %s", string(sshConn.ClientVersion())))

	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	// --- Step 5: Verify data channel ---
	step++
	if *shellMode {
		logStep(step, "Opening interactive shell session")
		if err := runShell(client); err != nil {
			logErr(fmt.Sprintf("Shell session error: %v", err))
			os.Exit(1)
		}
	} else {
		execCmd := "?"
		if *cmd != "" {
			execCmd = *cmd
		}
		logStep(step, fmt.Sprintf("Executing command: %s", execCmd))
		if err := runCommand(client, execCmd); err != nil {
			logErr(fmt.Sprintf("Command execution failed: %v", err))
			os.Exit(1)
		}
	}

	// --- Summary ---
	fmt.Printf("\n%s╔══════════════════════════════════════════════════╗%s\n", colorGreen, colorReset)
	fmt.Printf("%s║    All GM/T 0129 tests PASSED                    ║%s\n", colorGreen, colorReset)
	fmt.Printf("%s╚══════════════════════════════════════════════════╝%s\n", colorGreen, colorReset)
	fmt.Printf("  Total time: %v\n\n", time.Since(startTime).Round(time.Millisecond))
}

// runCommand executes a single command over the SSH session.
func runCommand(client *ssh.Client, cmd string) error {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(cmd)
	if err != nil {
		return fmt.Errorf("run command: %w", err)
	}

	logOK(fmt.Sprintf("Output:\n%s", strings.TrimSpace(string(output))))
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

	logOK("Interactive shell started (type 'exit' to quit)")
	return session.Wait()
}

// fingerprint returns a SHA256 fingerprint of a public key.
func fingerprint(key ssh.PublicKey) string {
	h := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.StdEncoding.EncodeToString(h[:])
}
