package tls

import (
	"crypto/tls"
	"fmt"
	"github.com/mzz2017/softwind/netproxy"
)

// Tls is a base Tls struct
type Tls struct {
	NextDialer netproxy.Dialer
	Addr       string
	TlsConfig  *tls.Config
}

func (s *Tls) Dial(network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		return s.DialTcp(addr)
	case "udp":
		return s.DialUdp(addr)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (s *Tls) DialUdp(addr string) (conn netproxy.PacketConn, err error) {
	return nil, fmt.Errorf("%w: tls+udp", netproxy.UnsupportedTunnelTypeError)
}

func (s *Tls) DialTcp(addr string) (conn netproxy.Conn, err error) {
	rc, err := s.NextDialer.DialTcp(addr)
	if err != nil {
		return nil, fmt.Errorf("[Tls]: dial to %s: %w", s.Addr, err)
	}

	tlsConn := tls.Client(&netproxy.FakeNetConn{
		Conn:  rc,
		LAddr: nil,
		RAddr: nil,
	}, s.TlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return tlsConn, err
}
