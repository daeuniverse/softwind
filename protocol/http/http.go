package http

import (
	"fmt"
	"github.com/mzz2017/softwind/netproxy"
	tls2 "github.com/mzz2017/softwind/transport/tls"
	"net/url"
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

		tlsImplementation := "tls"
		if u.Query().Has("tlsImplementation") {
			tlsImplementation = u.Query().Get("tlsImplementation")
		}
		u := url.URL{
			Scheme: tlsImplementation,
			Host:   s.Host,
			RawQuery: url.Values{
				"sni":           []string{serverName},
				"allowInsecure": []string{u.Query().Get("allowInsecure")},
				"utlsImitate":   []string{u.Query().Get("utlsImitate")},
				"alpn":          []string{"h2", "http/1.1"},
			}.Encode(),
		}
		var err error
		s.dialer, err = tls2.NewTls(u.String(), s.dialer)
		if err != nil {
			return nil, err
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
