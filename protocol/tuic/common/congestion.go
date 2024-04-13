package common

import (
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/softwind/protocol/tuic/congestion"
)

const (
	InitialStreamReceiveWindow     = 2 * 1024 * 1024  // 2 MB
	MaxStreamReceiveWindow         = 32 * 1024 * 1024 // 32 MB
	InitialConnectionReceiveWindow = 32 * 1024 * 1024 // 32 MB
	MaxConnectionReceiveWindow     = 64 * 1024 * 1024 // 64 MB
)

func SetCongestionController(quicConn quic.Connection, cc string, cwnd int) {
	switch cc {
	default:
		fallthrough
	case "bbr":
		congestion.UseBBR(quicConn)
	}
}
