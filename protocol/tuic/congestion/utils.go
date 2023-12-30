package congestion

import (
	"github.com/daeuniverse/softwind/protocol/tuic/congestion/bbr"
	"github.com/daeuniverse/softwind/protocol/tuic/congestion/brutal"
	"github.com/mzz2017/quic-go"
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
