package direct

import (
	"github.com/mzz2017/softwind/netproxy"
	"net"
	"net/netip"
)

var SymmetricDirect = newDirect(false)
var FullconeDirect = newDirect(true)

type direct struct {
	netproxy.Dialer
	fullCone   bool
}

func newDirect(fullCone bool) netproxy.Dialer {
	return &direct{
		fullCone:   fullCone,
	}
}

func (d *direct) DialUdp(addr string) (c netproxy.PacketConn, err error) {

	if d.fullCone {
		conn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, err
		}
		return &directUDPConn{UDPConn: conn, FullCone: true}, nil
	} else {
		conn, err := net.Dial("udp", addr)
		if err != nil {
			return nil, err
		}
		return &directUDPConn{UDPConn: conn.(*net.UDPConn), FullCone: false}, nil
	}
}

func (d *direct) DialTcp(addr string) (c netproxy.Conn, err error) {
	conn, err := net.Dial("tcp", addr)
	return conn.(*net.TCPConn), err
}

type directUDPConn struct {
	*net.UDPConn
	FullCone bool
}

func (c *directUDPConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return c.UDPConn.ReadFromUDPAddrPort(p)
}

func (c *directUDPConn) WriteTo(b []byte, addr string) (int, error) {
	if !c.FullCone {
		// FIXME: check the addr
		return c.Write(b)
	}
	uAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return 0, err
	}
	return c.UDPConn.WriteTo(b, uAddr)
}

func (c *directUDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	if !c.FullCone {
		n, err = c.Write(b)
		return n, 0, err
	}
	return c.UDPConn.WriteMsgUDP(b, oob, addr)
}

func (c *directUDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	if !c.FullCone {
		return c.Write(b)
	}
	return c.UDPConn.WriteToUDP(b, addr)
}
