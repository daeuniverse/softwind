package juicity

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/daeuniverse/softwind/ciphers"
	"github.com/daeuniverse/softwind/pkg/fastrand"
	"github.com/daeuniverse/softwind/pool"
	"github.com/daeuniverse/softwind/protocol/shadowsocks"
	"github.com/mzz2017/quic-go"
)

type TransportPacketConn struct {
	*quic.Transport
	tgt      *net.UDPAddr
	netipTgt netip.AddrPort
	key      *shadowsocks.Key
}

// SetDeadline implements netproxy.Conn.
func (c *TransportPacketConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

// SetReadDeadline implements netproxy.Conn.
func (c *TransportPacketConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline implements netproxy.Conn.
func (c *TransportPacketConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

func (c *TransportPacketConn) Write(b []byte) (int, error) {
	salt := pool.Get(c.key.CipherConf.SaltLen)
	defer salt.Put()
	fastrand.Read(salt)
	salt[0] = 0
	salt[1] = 0
	toWrite, err := shadowsocks.EncryptUDPFromPool(c.key, b, salt, ciphers.JuicityReusedInfo)
	if err != nil {
		return 0, err
	}
	defer toWrite.Put()
	return c.Transport.WriteTo(toWrite, c.tgt)
}

func (c *TransportPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return n, err
}

func (c *TransportPacketConn) ReadFrom(p []byte) (n int, addrPort netip.AddrPort, err error) {
	n, _, err = c.Transport.ReadNonQUICPacket(context.TODO(), p)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	buf, err := shadowsocks.DecryptUDPFromPool(c.key, p[:n], ciphers.JuicityReusedInfo)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	defer buf.Put()
	n = copy(p, buf)
	return n, c.netipTgt, nil
}

func (c *TransportPacketConn) WriteTo(p []byte, addr string) (n int, err error) {
	return c.Write(p)
}

func (c *TransportPacketConn) Close() error {
	return c.Conn.Close()
}
