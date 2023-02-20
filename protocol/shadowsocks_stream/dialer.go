package shadowsocks_stream

import (
	"fmt"
	"github.com/mzz2017/softwind/ciphers"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/protocol"
	"github.com/mzz2017/softwind/protocol/infra/socks"
)

func init() {
	protocol.Register("shadowsocks_stream", NewDialer)
}

const (
	TransportMagicAddr = "<TRANSPORT>"
)

type Dialer struct {
	nextDialer netproxy.Dialer
	addr       string

	EncryptMethod   string
	EncryptPassword string
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	return &Dialer{
		nextDialer:      nextDialer,
		addr:            header.ProxyAddress,
		EncryptMethod:   header.Cipher,
		EncryptPassword: header.Password,
	}, nil
}

// Addr returns forwarder's address
func (d *Dialer) Addr() string {
	return d.addr
}

func (d *Dialer) Dial(network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		return d.DialTcp(addr)
	case "udp":
		return d.DialUdp(addr)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

// DialTcp connects to the address addr on the network net via the proxy.
func (d *Dialer) DialTcp(addr string) (netproxy.Conn, error) {
	target, err := socks.ParseAddr(addr)
	if err != nil {
		return nil, err
	}

	conn, err := d.DialTcpTransport()
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write(target); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, err
}

func (d *Dialer) DialTcpTransport() (netproxy.Conn, error) {
	ciph, err := ciphers.NewStreamCipher(d.EncryptMethod, d.EncryptPassword)
	if err != nil {
		return nil, err
	}

	c, err := d.nextDialer.DialTcp(d.addr)
	if err != nil {
		return nil, fmt.Errorf("dial to %v error: %w", d.addr, err)
	}

	conn := NewTcpConn(c, ciph)

	return conn, err
}

// DialUdp connects to the given address via the proxy.
func (d *Dialer) DialUdp(addr string) (c netproxy.PacketConn, err error) {
	var target socks.Addr
	if addr != TransportMagicAddr {
		target, err = socks.ParseAddr(addr)
		if err != nil {
			return nil, err
		}
	}

	ciph, err := ciphers.NewStreamCipher(d.EncryptMethod, d.EncryptPassword)
	if err != nil {
		return nil, err
	}

	c, err = d.nextDialer.DialUdp(d.addr)
	if err != nil {
		return nil, fmt.Errorf("dial to %v error: %w", d.addr, err)
	}
	return NewUdpConn(c, ciph, target, d.addr), nil
}

func (d *Dialer) DialUdpTransport() (netproxy.PacketConn, error) {
	conn, err := d.DialUdp(TransportMagicAddr)
	if err != nil {
		return nil, err
	}
	return &UdpTransportConn{UdpConn: conn.(*UdpConn)}, nil
}
