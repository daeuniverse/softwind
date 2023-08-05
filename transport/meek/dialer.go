package meek

import (
	"context"
	"fmt"
	"net/url"

	"github.com/daeuniverse/softwind/netproxy"
)

type Dialer struct {
	nextDialer netproxy.Dialer
	addr       string
	url        string
}

func NewDialer(s string, d netproxy.Dialer) (*Dialer, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("NewMeek: %w", err)
	}

	m := &Dialer{
		nextDialer: d,
		addr:       u.Host,
	}

	query := u.Query()
	m.url = query.Get("url")
	if m.url == "" {
		return nil, fmt.Errorf("NewMeek: url is empty")
	}

	meekUrl, err := url.Parse(m.url)
	if err != nil {
		return nil, fmt.Errorf("NewMeek: %w", err)
	}
	if meekUrl.Scheme != "https" {
		return nil, fmt.Errorf("NewMeek: unimplemented backdrop")
	}

	return m, nil
}

func (m *Dialer) Dial(network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		tripper := &httpTripperClient{
			nextDialer: m.nextDialer,
			addr:       m.addr,
			url:        m.url,
		}

		clientConfig := &config{
			MaxWriteSize:             65536,
			WaitSubsequentWriteMs:    10,
			InitialPollingIntervalMs: 100,
			MaxPollingIntervalMs:     1000,
			MinPollingIntervalMs:     10,
			BackoffFactor:            1.5,
			FailedRetryIntervalMs:    1000,
		}

		assembler := newAssemblerClient(tripper, clientConfig)
		session, err := assembler.NewSession(context.Background())
		if err != nil {
			return nil, err
		}

		return session.(netproxy.Conn), nil
	case "udp":
		return nil, fmt.Errorf("%w: meek+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
