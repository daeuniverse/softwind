package http

import (
	"crypto/tls"
	"github.com/mzz2017/softwind/netproxy"
	"net/url"
	"strconv"
)

// HttpProxy is an HTTP/HTTPS proxy.
type HttpProxy struct {
	TlsConfig *tls.Config
	Host      string
	HaveAuth  bool
	Username  string
	Password  string
	dialer    netproxy.Dialer
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
		serverName := u.Query().Get("sni")
		if serverName == "" {
			serverName = u.Hostname()
		}
		skipVerify, _ := strconv.ParseBool(u.Query().Get("allowInsecure"))
		s.TlsConfig = &tls.Config{
			NextProtos:         []string{"h2", "http/1.1"},
			ServerName:         serverName,
			InsecureSkipVerify: skipVerify,
		}
	}
	return s, nil
}

func (s *HttpProxy) DialUdp(addr string) (netproxy.PacketConn, error) {
	return nil, netproxy.UnsupportedTunnelTypeError
}

func (s *HttpProxy) DialTcp(addr string) (netproxy.Conn, error) {
	// DialTcp and create the https client connection.
	c, err := s.dialer.DialTcp(s.Host)
	if err != nil {
		return nil, err
	}
	if s.TlsConfig != nil {
		c = tls.Client(&netproxy.FakeNetConn{
			Conn:  c,
			LAddr: nil,
			RAddr: nil,
		}, s.TlsConfig)
	}
	return NewConn(c, s, addr), nil
}
