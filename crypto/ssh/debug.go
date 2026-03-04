package ssh

import "fmt"

// Debug verbosity levels, matching OpenSSH conventions.
const (
	debugLevel1 = 1 // high-level protocol events
	debugLevel2 = 2 // algorithm proposals, negotiation details
	debugLevel3 = 3 // raw packet types, crypto details
)

// debugLogger is the package-level debug logging function.
// Set via SetDebugLogger. nil means no debug output.
var debugLogger func(level int, format string, args ...interface{})

// SetDebugLogger configures a debug logging function for the SSH library.
// The level parameter indicates verbosity (1=high-level, 2=detail, 3=trace).
// Pass nil to disable debug logging.
func SetDebugLogger(fn func(level int, format string, args ...interface{})) {
	debugLogger = fn
}

func debugf(level int, format string, args ...interface{}) {
	if debugLogger != nil {
		debugLogger(level, format, args...)
	}
}

// msgTypeStr returns a human-readable name for an SSH message type byte.
func msgTypeStr(t uint8) string {
	switch t {
	case msgDisconnect:
		return "SSH_MSG_DISCONNECT"
	case msgIgnore:
		return "SSH_MSG_IGNORE"
	case msgUnimplemented:
		return "SSH_MSG_UNIMPLEMENTED"
	case msgDebug:
		return "SSH_MSG_DEBUG"
	case msgServiceRequest:
		return "SSH_MSG_SERVICE_REQUEST"
	case msgServiceAccept:
		return "SSH_MSG_SERVICE_ACCEPT"
	case msgExtInfo:
		return "SSH_MSG_EXT_INFO"
	case msgKexInit:
		return "SSH_MSG_KEXINIT"
	case msgNewKeys:
		return "SSH_MSG_NEWKEYS"
	case msgUserAuthRequest:
		return "SSH_MSG_USERAUTH_REQUEST"
	case msgUserAuthSuccess:
		return "SSH_MSG_USERAUTH_SUCCESS"
	case msgUserAuthFailure:
		return "SSH_MSG_USERAUTH_FAILURE"
	case msgUserAuthBanner:
		return "SSH_MSG_USERAUTH_BANNER"
	case msgUserAuthPubKeyOk:
		return "SSH_MSG_USERAUTH_PK_OK"
	case msgGlobalRequest:
		return "SSH_MSG_GLOBAL_REQUEST"
	case msgRequestSuccess:
		return "SSH_MSG_REQUEST_SUCCESS"
	case msgRequestFailure:
		return "SSH_MSG_REQUEST_FAILURE"
	case msgChannelOpen:
		return "SSH_MSG_CHANNEL_OPEN"
	case msgChannelOpenConfirm:
		return "SSH_MSG_CHANNEL_OPEN_CONFIRMATION"
	case msgChannelOpenFailure:
		return "SSH_MSG_CHANNEL_OPEN_FAILURE"
	case msgChannelWindowAdjust:
		return "SSH_MSG_CHANNEL_WINDOW_ADJUST"
	case msgChannelData:
		return "SSH_MSG_CHANNEL_DATA"
	case msgChannelExtendedData:
		return "SSH_MSG_CHANNEL_EXTENDED_DATA"
	case msgChannelEOF:
		return "SSH_MSG_CHANNEL_EOF"
	case msgChannelClose:
		return "SSH_MSG_CHANNEL_CLOSE"
	case msgChannelRequest:
		return "SSH_MSG_CHANNEL_REQUEST"
	case msgChannelSuccess:
		return "SSH_MSG_CHANNEL_SUCCESS"
	case msgChannelFailure:
		return "SSH_MSG_CHANNEL_FAILURE"
	case msgGMKexRequest:
		return "SSH_MSG_GM_KEX_REQUEST(200)"
	case msgGMKexReply:
		return "SSH_MSG_GM_KEX_REPLY(201)"
	case msgGMKex:
		return "SSH_MSG_GM_KEX(202)"
	case msgGMUserAuthChallenge:
		return "SSH_MSG_GM_USERAUTH_CHALLENGE(210)"
	case msgGMUserAuthRespond:
		return "SSH_MSG_GM_USERAUTH_RESPOND(211)"
	default:
		return fmt.Sprintf("type %d", t)
	}
}
