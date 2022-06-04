package trojanc

import (
	"github.com/mzz2017/softwind/protocol"
	"net"
	"strconv"
)

func (c *Conn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// FIXME: a compromise on Symmetric NAT
	if c.cachedRAddrIP == nil {
		c.cachedRAddrIP, err = net.ResolveUDPAddr("udp", net.JoinHostPort(c.metadata.Hostname, strconv.Itoa(int(c.metadata.Port))))
		if err != nil {
			return 0, nil, err
		}
	}
	addr = c.cachedRAddrIP
	n, err = c.Read(p)
	return n, addr, err
}

func (c *Conn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.Write(p)
}

func (c *Conn) LocalAddr() net.Addr {
	switch c.metadata.Network {
	case "udp":
		return protocol.TCPAddrToUDPAddr(c.Conn.LocalAddr().(*net.TCPAddr))
	default:
		return c.Conn.LocalAddr()
	}
}

func (c *Conn) RemoteAddr() net.Addr {
	switch c.metadata.Network {
	case "udp":
		return protocol.TCPAddrToUDPAddr(c.Conn.RemoteAddr().(*net.TCPAddr))
	default:
		return c.Conn.RemoteAddr()
	}
}

