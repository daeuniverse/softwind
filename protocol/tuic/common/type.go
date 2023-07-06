package common

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/mzz2017/quic-go"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/protocol"
)

var (
	ErrClientClosed       = errors.New("client closed")
	ErrTooManyOpenStreams = errors.New("too many open streams")
	ErrHoldOn             = errors.New("hold on")
)

type DialFunc func(ctx context.Context, dialer netproxy.Dialer) (transport *quic.Transport, addr net.Addr, err error)

type Client interface {
	DialContextWithDialer(ctx context.Context, metadata *protocol.Metadata, dialer netproxy.Dialer, dialFn DialFunc) (netproxy.Conn, error)
	ListenPacketWithDialer(ctx context.Context, metadata *protocol.Metadata, dialer netproxy.Dialer, dialFn DialFunc) (netproxy.PacketConn, error)
	OpenStreams() int64
	LastVisited() time.Time
	SetLastVisited(last time.Time)
	Close()
}

type UdpRelayMode uint8

const (
	QUIC UdpRelayMode = iota
	NATIVE
)
