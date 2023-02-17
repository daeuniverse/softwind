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
func (s *Dialer) Addr() string {
	return s.addr
}

// DialTcp connects to the address addr on the network net via the proxy.
func (s *Dialer) DialTcp(addr string) (netproxy.Conn, error) {
	target, err := socks.ParseAddr(addr)
	if err != nil {
		return nil, err
	}

	conn, err := s.DialTcpTransport()
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write(target); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, err
}

func (s *Dialer) DialTcpTransport() (netproxy.Conn, error) {
	ciph, err := ciphers.NewStreamCipher(s.EncryptMethod, s.EncryptPassword)
	if err != nil {
		return nil, err
	}

	c, err := s.nextDialer.DialTcp(s.addr)
	if err != nil {
		return nil, fmt.Errorf("dial to %s error: %w", s.addr, err)
	}

	conn := NewTcpConn(c, ciph)

	return conn, err
}

// DialUdp connects to the given address via the proxy.
func (s *Dialer) DialUdp(addr string) (c netproxy.PacketConn, err error) {
	var target socks.Addr
	if addr != TransportMagicAddr {
		target, err = socks.ParseAddr(addr)
		if err != nil {
			return nil, err
		}
	}

	ciph, err := ciphers.NewStreamCipher(s.EncryptMethod, s.EncryptPassword)
	if err != nil {
		return nil, err
	}

	c, err = s.nextDialer.DialUdp(s.addr)
	if err != nil {
		return nil, fmt.Errorf("dial to %s error: %w", s.addr, err)
	}
	return NewUdpConn(c, ciph, target, s.addr), nil
}

func (s *Dialer) DialUdpTransport() (netproxy.PacketConn, error) {
	conn, err := s.DialUdp(TransportMagicAddr)
	if err != nil {
		return nil, err
	}
	return &UdpTransportConn{UdpConn: conn.(*UdpConn)}, nil
}
