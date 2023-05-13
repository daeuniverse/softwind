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
		rc, err := s.NextDialer.Dial(network, addr)
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
	case "udp":
		return nil, fmt.Errorf("%w: tls+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
