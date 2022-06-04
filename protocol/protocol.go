package protocol

import (
	"context"
	"fmt"
	"golang.org/x/net/proxy"
	"net"
)

var (
	ErrFailAuth     = fmt.Errorf("fail to authenticate")
	ErrReplayAttack = fmt.Errorf("replay attack")
)

type Protocol string

const (
	ProtocolVMessTCP     Protocol = "vmess"
	ProtocolVMessTlsGrpc Protocol = "vmess+tls+grpc"
	ProtocolShadowsocks  Protocol = "shadowsocks"
)

func (p Protocol) Valid() bool {
	switch p {
	case ProtocolVMessTCP, ProtocolVMessTlsGrpc, ProtocolShadowsocks:
		return true
	default:
		return false
	}
}

type DialerConverter struct {
	Dialer proxy.Dialer
}

func (d *DialerConverter) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	var done = make(chan struct{})
	go func() {
		c, err = d.Dialer.Dial(network, addr)
		if err != nil {
			return
		}
		select {
		case <-ctx.Done():
			_ = c.Close()
		default:
			close(done)
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
		return c, err
	}
}

func (d *DialerConverter) Dial(network, addr string) (c net.Conn, err error) {
	return d.Dialer.Dial(network, addr)
}
