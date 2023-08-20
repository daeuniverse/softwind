package common

import (
	"github.com/daeuniverse/softwind/protocol/tuic/congestion"
	"github.com/mzz2017/quic-go"
	c "github.com/mzz2017/quic-go/congestion"
)

const (
	InitialStreamReceiveWindow     = 8 * 1024 * 1024  // 8 MB
	MaxStreamReceiveWindow         = 32 * 1024 * 1024 // 32 MB
	InitialConnectionReceiveWindow = 32 * 1024 * 1024 // 32 MB
	MaxConnectionReceiveWindow     = 64 * 1024 * 1024 // 64 MB
)

func SetCongestionController(quicConn quic.Connection, cc string, cwnd int) {
	CWND := c.ByteCount(cwnd)
	switch cc {
	case "cubic":
		quicConn.SetCongestionControl(
			congestion.NewCubicSender(
				congestion.DefaultClock{},
				congestion.GetInitialPacketSize(quicConn.RemoteAddr()),
				false,
				nil,
			),
		)
	case "new_reno":
		quicConn.SetCongestionControl(
			congestion.NewCubicSender(
				congestion.DefaultClock{},
				congestion.GetInitialPacketSize(quicConn.RemoteAddr()),
				true,
				nil,
			),
		)
	case "bbr":
		fallthrough
	default:
		quicConn.SetCongestionControl(
			congestion.NewBBRSender(
				congestion.DefaultClock{},
				congestion.GetInitialPacketSize(quicConn.RemoteAddr()),
				CWND*congestion.InitialMaxDatagramSize,
				200*congestion.InitialMaxDatagramSize,
			),
		)
	}
}
