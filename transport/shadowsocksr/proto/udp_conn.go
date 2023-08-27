package proto

import (
	"fmt"
	"net/netip"

	"github.com/daeuniverse/softwind/ciphers"
	"github.com/daeuniverse/softwind/netproxy"
	"github.com/daeuniverse/softwind/pool"
	"github.com/daeuniverse/softwind/protocol/infra/socks"
	"github.com/daeuniverse/softwind/protocol/shadowsocks_stream"
)

type PacketConn struct {
	netproxy.PacketConn
	Protocol IProtocol
	tgt      string
}

func NewPacketConn(c netproxy.PacketConn, proto IProtocol, tgt string) (*PacketConn, error) {
	return &PacketConn{
		PacketConn: c,
		Protocol:   proto,
		tgt:        tgt,
	}, nil
}

func (c *PacketConn) InnerCipher() *ciphers.StreamCipher {
	switch innerConn := c.PacketConn.(type) {
	case *shadowsocks_stream.UdpConn:
		return innerConn.Cipher()
	default:
		return nil
	}
}

func (c *PacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return n, err
}

func (c *PacketConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.tgt)
}

func (c *PacketConn) ReadFrom(b []byte) (n int, from netip.AddrPort, err error) {
	n, err = c.PacketConn.Read(b)
	if err != nil {
		return n, netip.AddrPort{}, err
	}
	decoded, err := c.Protocol.DecodePkt(b[:n])
	if err != nil {
		return n, netip.AddrPort{}, err
	}
	defer decoded.Put()

	addr := socks.SplitAddr(decoded.Bytes())
	if addr == nil {
		return 0, netip.AddrPort{}, fmt.Errorf("no addr present")
	}

	from, err = netip.ParseAddrPort(addr.String())
	if err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("bad addr: %w", err)
	}

	//if len(b) < len(decoded.Bytes())-len(addr) {
	//	return 0, netip.AddrPort{}, fmt.Errorf("buffer is not enough to read")
	//}
	n = copy(b, decoded.Bytes()[len(addr):])
	return n, from, nil
}

func (c *PacketConn) WriteTo(b []byte, to string) (n int, err error) {
	addr, err := socks.ParseAddr(to)
	if err != nil {
		return 0, err
	}
	pb := pool.GetMustBigger(len(addr) + len(b))
	copy(pb, addr)
	copy(pb[len(addr):], b)
	buf := pool.NewBufferFrom(pb)
	if err = c.Protocol.EncodePkt(buf); err != nil {
		return 0, err
	}
	defer buf.Put()
	if _, err = c.PacketConn.Write(buf.Bytes()); err != nil {
		return 0, err
	}

	return len(b), err
}
