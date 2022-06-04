package http

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"golang.org/x/net/proxy"
	"net"
	"net/http"
	"net/url"
)

// HttpProxy is an HTTP/HTTPS proxy.
type HttpProxy struct {
	TlsConfig *tls.Config
	Host      string
	HaveAuth  bool
	Username  string
	Password  string
	dialer    proxy.Dialer
}

func NewHTTPProxy(u *url.URL, forward proxy.Dialer) (proxy.Dialer, error) {
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
		s.TlsConfig = &tls.Config{
			NextProtos: []string{"h2", "http/1.1"},
			ServerName: serverName,
		}
	}
	return s, nil
}

func (s *HttpProxy) Dial(network, addr string) (net.Conn, error) {
	// Dial and create the https client connection.
	c, err := s.dialer.Dial("tcp", s.Host)
	if err != nil {
		return nil, err
	}
	if s.TlsConfig != nil {
		c = tls.Client(c, s.TlsConfig)
	}
	// HACK. http.ReadRequest also does this.
	reqURL, err := url.Parse("http://" + addr)
	if err != nil {
		c.Close()
		return nil, err
	}
	reqURL.Scheme = ""

	req, err := http.NewRequest("CONNECT", reqURL.String(), nil)
	if err != nil {
		c.Close()
		return nil, err
	}
	req.Close = false
	if s.HaveAuth {
		req.SetBasicAuth(s.Username, s.Password)
		req.Header.Set("Proxy-Authorization", req.Header.Get("Authorization"))
		req.Header.Del("Authorization")
	}

	err = req.Write(c)
	if err != nil {
		c.Close()
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		c.Close()
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		c.Close()
		err = fmt.Errorf("Connect server using proxy error, StatusCode [%d]", resp.StatusCode)
		return nil, err
	}

	return c, nil
}
