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

	url string
}

func (c *httpTripperClient) RoundTrip(ctx context.Context, req Request) (resp Response, err error) {
	connectionTagStr := base64.RawURLEncoding.EncodeToString(req.ConnectionTag)

	httpRequest, err := http.NewRequest("POST", c.url, bytes.NewReader(req.Data))
	if err != nil {
		return
	}
	httpRequest.Header.Set("X-Session-ID", connectionTagStr)

	transport := &http.Transport{
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
	httpResp, err := transport.RoundTrip(httpRequest)
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
