package congestion

import (
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/softwind/protocol/tuic/congestion/bbr"
	"github.com/daeuniverse/softwind/protocol/tuic/congestion/brutal"
)

func UseBBR(conn quic.Connection) {
	conn.SetCongestionControl(bbr.NewBbrSender(
		bbr.DefaultClock{},
		bbr.GetInitialPacketSize(conn.RemoteAddr()),
	))
}

func UseBrutal(conn quic.Connection, tx uint64) {
	conn.SetCongestionControl(brutal.NewBrutalSender(tx))
}
