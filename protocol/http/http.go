package http

import (
	"crypto/tls"
	"fmt"
	"github.com/mzz2017/softwind/netproxy"
	tls2 "github.com/mzz2017/softwind/transport/tls"
	"net/url"
	"strconv"
)

// HttpProxy is an HTTP/HTTPS proxy.
type HttpProxy struct {
	https    bool
	Host     string
	HaveAuth bool
	Username string
	Password string
	dialer   netproxy.Dialer
}

func NewHTTPProxy(u *url.URL, forward netproxy.Dialer) (netproxy.Dialer, error) {
	s := new(HttpProxy)
	s.Host = u.Host
	s.dialer = forward
	if u.User != nil {
		s.HaveAuth = true
		s.Username = u.User.Username()
		s.Password, _ = u.User.Password()
	}
	if u.Scheme == "https" {
		s.https = true
		serverName := u.Query().Get("sni")
		if serverName == "" {
			serverName = u.Hostname()
		}
		skipVerify, _ := strconv.ParseBool(u.Query().Get("allowInsecure"))
		s.dialer = &tls2.Tls{
			NextDialer: s.dialer,
			Addr:       s.Host,
			TlsConfig: &tls.Config{
				NextProtos:         []string{"h2", "http/1.1"},
				ServerName:         serverName,
				InsecureSkipVerify: skipVerify,
			},
		}
	}
	return s, nil
}

func (s *HttpProxy) Dial(network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		return NewConn(s.dialer, s, addr, network), nil
	case "udp":
		return nil, netproxy.UnsupportedTunnelTypeError
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
