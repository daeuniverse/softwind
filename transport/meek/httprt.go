package meek

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/daeuniverse/softwind/netproxy"
)

type httpTripperClient struct {
	addr       string
	nextDialer netproxy.Dialer
	tlsConfig  *tls.Config
	url        string

	roundTripper http.RoundTripper
}

func (c *httpTripperClient) RoundTrip(ctx context.Context, req Request) (resp Response, err error) {
	if c.roundTripper == nil {
		c.roundTripper = &http.Transport{
			DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				rc, err := c.nextDialer.Dial(network, addr)
				if err != nil {
					return nil, fmt.Errorf("[Meek]: dial to %s: %w", c.addr, err)
				}
				return &netproxy.FakeNetConn{
					Conn:  rc,
					LAddr: nil,
					RAddr: nil,
				}, nil
			},
			TLSClientConfig: c.tlsConfig,
		}
	}

	connectionTagStr := base64.RawURLEncoding.EncodeToString(req.ConnectionTag)

	httpRequest, err := http.NewRequest("POST", c.url, bytes.NewReader(req.Data))
	if err != nil {
		return
	}
	httpRequest.Header.Set("X-Session-ID", connectionTagStr)

	httpResp, err := c.roundTripper.RoundTrip(httpRequest)
	if err != nil {
		return
	}
	defer httpResp.Body.Close()

	result, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return
	}
	return Response{Data: result}, err
}
