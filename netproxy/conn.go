package netproxy

import (
	"fmt"
	"net"
	"net/netip"
	"time"
)

var UnsupportedTunnelTypeError = fmt.Errorf("unsupported tunnel type")

type FullConn interface {
	Conn
	PacketConn
}

type Conn interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

type PacketConn interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	ReadFrom(p []byte) (n int, addr netip.AddrPort, err error)
	WriteTo(p []byte, addr string) (n int, err error)
	Close() error
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

type FakeNetConn struct {
	Conn
	LAddr net.Addr
	RAddr net.Addr
}

func (conn *FakeNetConn) LocalAddr() net.Addr {
	return conn.LAddr
}

func (conn *FakeNetConn) RemoteAddr() net.Addr {
	return conn.RAddr
}
