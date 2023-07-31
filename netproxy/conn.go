package netproxy

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

var UnsupportedTunnelTypeError = net.UnknownNetworkError("unsupported tunnel type")

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

type FakeNetPacketConn struct {
	PacketConn
	LAddr net.Addr
	RAddr net.Addr
}

func (conn *FakeNetPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, a, err := conn.PacketConn.ReadFrom(p)
	return n, net.UDPAddrFromAddrPort(a), err
}
func (conn *FakeNetPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return conn.PacketConn.WriteTo(p, addr.String())
}
func (conn *FakeNetPacketConn) LocalAddr() net.Addr {
	return conn.LAddr
}
func (conn *FakeNetPacketConn) RemoteAddr() net.Addr {
	return conn.RAddr
}
func (conn *FakeNetPacketConn) SetWriteBuffer(size int) error {
	c, ok := conn.PacketConn.(interface{ SetWriteBuffer(int) error })
	if !ok {
		return fmt.Errorf("connection doesn't allow setting of send buffer size. Not a *net.UDPConn?")
	}
	return c.SetWriteBuffer(size)
}
func (conn *FakeNetPacketConn) SetReadBuffer(size int) error {
	c, ok := conn.PacketConn.(interface{ SetReadBuffer(int) error })
	if !ok {
		return fmt.Errorf("connection doesn't allow setting of send buffer size. Not a *net.UDPConn?")
	}
	return c.SetReadBuffer(size)
}
func (conn *FakeNetPacketConn) SyscallConn() (syscall.RawConn, error) {
	c, ok := conn.PacketConn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return nil, fmt.Errorf("connection doesn't allow to get Syscall.RawConn. Not a *net.UDPConn?")
	}
	return c.SyscallConn()
}
