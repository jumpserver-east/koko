package sshd

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/pires/go-proxyproto"
	gossh "golang.org/x/crypto/ssh"

	"github.com/jumpserver-dev/sdk-go/service"
	"github.com/jumpserver/koko/pkg/config"
	"github.com/jumpserver/koko/pkg/handler"
	"github.com/jumpserver/koko/pkg/logger"
)

const (
	sshChannelSession     = "session"
	sshChannelDirectTCPIP = "direct-tcpip"
	sshSubSystemSFTP      = "sftp"

	ChannelTCPIPForward       = "tcpip-forward"
	ChannelCancelTCPIPForward = "cancel-tcpip-forward"
	ChannelForwardedTCPIP     = "forwarded-tcpip"
)

var (
	supportedMACs = []string{
		"hmac-sm3", "cbc-mac",
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-256", "hmac-sha1",
	}

	supportedKexAlgos = []string{
		"sm2-sm3", "ecdh-sm2p256v1-sm3",
		"curve25519-sha256", "curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
	}

	supportedCiphers = []string{
		"sm4-gcm", "sm4-ctr", "sm4-cbc",
		"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
		"chacha20-poly1305@openssh.com",
		"aes128-ctr", "aes192-ctr", "aes256-ctr",
	}

	// 国密专用算法集合 (GM/T 0129-2023)。开启 SSH_GM_ONLY 时，SSH 服务端只协商
	// 下列国密算法，参考 cmd/gmssh、cmd/gmsshd 的实现。
	gmOnlyMACs      = []string{"hmac-sm3", "cbc-mac"}
	gmOnlyKexAlgos  = []string{"sm2-sm3", "ecdh-sm2p256v1-sm3"}
	gmOnlyCiphers   = []string{"sm4-gcm", "sm4-ctr", "sm4-cbc"}
	gmOnlyPubKeyAlg = []string{gossh.KeyAlgoSM2}

	defaultPubKeyAlgorithms = []string{
		gossh.KeyAlgoSM2,
		gossh.KeyAlgoED25519,
		gossh.KeyAlgoSKED25519,
		gossh.KeyAlgoSKECDSA256,
		gossh.KeyAlgoECDSA256,
		gossh.KeyAlgoECDSA384,
		gossh.KeyAlgoECDSA521,
		gossh.KeyAlgoRSASHA256,
		gossh.KeyAlgoRSASHA512,
	}
)

type Server struct {
	Srv     *ssh.Server
	Handler *handler.Server
}

func (s *Server) Start() {
	logger.Infof("Start SSH server at %s", s.Srv.Addr)
	ln, err := net.Listen("tcp", s.Srv.Addr)
	if err != nil {
		logger.Fatal(err)
	}
	proxyListener := &proxyproto.Listener{Listener: ln}
	logger.Fatal(s.Srv.Serve(proxyListener))
}

func (s *Server) Stop() {
	ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFunc()
	logger.Fatal(s.Srv.Shutdown(ctx))
}

func NewSSHServer(jmsService *service.JMService) *Server {
	cf := config.GlobalConfig
	addr := net.JoinHostPort(cf.BindHost, cf.SSHPort)
	termCfg, err := jmsService.GetTerminalConfig()
	if err != nil {
		logger.Fatal(err)
	}
	singer, err := ParsePrivateKeyFromString(termCfg.HostKey)
	if err != nil {
		logger.Fatalf("Parse Terminal private key failed: %s\n", err)
	}
	sm2Signer, err := GenerateSM2HostKey()
	if err != nil {
		logger.Errorf("Generate SM2 host key failed: %s", err)
	}
	hostSigners := []ssh.Signer{sm2Signer, singer}
	if cf.SSHGMOnly {
		logger.Info("SSH GM-only mode enabled: only national-cryptography (GM/T 0129) algorithms are negotiated")
	}
	sshHandler := handler.NewServer(termCfg, jmsService)
	srv := &ssh.Server{
		Addr:             addr,
		PasswordHandler:  sshHandler.PasswordAuth,
		PublicKeyHandler: sshHandler.PublicKeyAuth,
		Version:          "CSSH-1.0-JumpServer",
		HostSigners:      hostSigners,
		MaxSessions:      int32(cf.SshMaxSessions),
		ServerConfigCallback: func(ctx ssh.Context) *gossh.ServerConfig {
			macs := supportedMACs
			kexAlgos := supportedKexAlgos
			ciphers := supportedCiphers
			pubKeyAlgos := defaultPubKeyAlgorithms
			omitKexExt := false
			if cf.SSHGMOnly {
				// 只保留国密算法。同时关闭 OpenSSH KEX 扩展 (含 strict KEX)，
				// 让 KEXINIT 算法名单保持纯国密，符合 GM/T 0129-2023。
				macs = gmOnlyMACs
				kexAlgos = gmOnlyKexAlgos
				ciphers = gmOnlyCiphers
				pubKeyAlgos = gmOnlyPubKeyAlg
				omitKexExt = true
			}
			cfg := gossh.Config{
				MACs:                     macs,
				KeyExchanges:             kexAlgos,
				Ciphers:                  ciphers,
				OmitOpenSSHKexExtensions: omitKexExt,
			}
			return &gossh.ServerConfig{
				Config:                  cfg,
				PublicKeyAuthAlgorithms: pubKeyAlgos,
			}
		},
		Handler:                       sshHandler.SessionHandler,
		LocalPortForwardingCallback:   sshHandler.LocalPortForwardingPermission,
		ReversePortForwardingCallback: sshHandler.ReversePortForwardingPermission,
		SubsystemHandlers:             map[string]ssh.SubsystemHandler{sshSubSystemSFTP: sshHandler.SFTPHandler},
		ChannelHandlers: map[string]ssh.ChannelHandler{
			sshChannelSession: ssh.DefaultSessionHandler,
			sshChannelDirectTCPIP: func(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
				localD := localForwardChannelData{}
				if err := gossh.Unmarshal(newChan.ExtraData(), &localD); err != nil {
					_ = newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
					return
				}

				if srv.LocalPortForwardingCallback == nil || !srv.LocalPortForwardingCallback(ctx, localD.DestAddr, localD.DestPort) {
					_ = newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
					return
				}
				dest := net.JoinHostPort(localD.DestAddr, strconv.FormatInt(int64(localD.DestPort), 10))
				sshHandler.DirectTCPIPChannelHandler(ctx, newChan, dest)
			},
		},
		RequestHandlers: map[string]ssh.RequestHandler{
			ChannelTCPIPForward:       sshHandler.HandleSSHRequest,
			ChannelCancelTCPIPForward: sshHandler.HandleSSHRequest,
		},
	}
	return &Server{srv, sshHandler}
}

type localForwardChannelData struct {
	DestAddr string
	DestPort uint32

	OriginAddr string
	OriginPort uint32
}
