package shadowsocks_stream

import (
	"fmt"
	"github.com/mzz2017/softwind/ciphers"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/pool"
	"github.com/mzz2017/softwind/protocol/infra/socks"
	"net/netip"
)

// UdpConn the struct that override the netproxy.Conn methods
type UdpConn struct {
	netproxy.PacketConn
	cipher         *ciphers.StreamCipher
	addr           socks.Addr
	cachedAddrPort netip.AddrPort
}

func NewUdpConn(c netproxy.PacketConn, cipher *ciphers.StreamCipher, addr socks.Addr) *UdpConn {
	return &UdpConn{
		PacketConn: c,
		cipher:     cipher,
		addr:       addr,
	}
}

func (c *UdpConn) ReadFrom(b []byte) (n int, from netip.AddrPort, err error) {
	n, from, err = c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, netip.AddrPort{}, err
	}
	if n < c.cipher.InfoIVLen() {
		return 0, netip.AddrPort{}, fmt.Errorf("packet too short")
	}
	dec, err := c.cipher.NewDecryptor(b[:c.cipher.InfoIVLen()])
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	dec.XORKeyStream(b[c.cipher.InfoIVLen():], b[c.cipher.InfoIVLen():])
	n = copy(b, b[c.cipher.InfoIVLen():])
	return n, from, nil
}

func (c *UdpConn) writeTo(p []byte, addr socks.Addr) (n int, err error) {
	infoIvLen := c.cipher.InfoIVLen()
	buf := pool.Get(infoIvLen + len(addr) + len(p))
	defer pool.Put(buf)
	enc, err := c.cipher.NewEncryptor(buf)
	if err != nil {
		return 0, err
	}
	copy(buf[infoIvLen:], addr)
	n = copy(buf[infoIvLen+len(addr):], p)
	enc.XORKeyStream(buf[infoIvLen+len(addr):], buf[infoIvLen+len(addr):])
	return n, nil
}

func (c *UdpConn) WriteTo(p []byte, to string) (n int, err error) {
	addr, err := socks.ParseAddr(to)
	if err != nil {
		return 0, err
	}
	return c.writeTo(p, addr)
}

func (c *UdpConn) Write(b []byte) (n int, err error) {
	return c.writeTo(b, c.addr)
}

func (c *UdpConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return n, err
}
