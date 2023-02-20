package netproxy

import (
	"context"
)

// A Dialer is a means to establish a connection.
// Custom dialers should also implement ContextDialer.
type Dialer interface {
	Dial(network string, addr string) (c Conn, err error)
	DialTcp(addr string) (c Conn, err error)
	DialUdp(addr string) (c PacketConn, err error)
}

type TcpDialer interface {
	DialTcp(addr string) (c Conn, err error)
}

type ContextDialer struct {
	Dialer
}

func DialContext(ctx context.Context, network, addr string, dial func(network, addr string) (c Conn, err error)) (c Conn, err error) {
	var done = make(chan struct{})
	go func() {
		c, err = dial(network, addr)
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

func (d *ContextDialer) DialContext(ctx context.Context, network, addr string) (c Conn, err error) {
	return DialContext(ctx, network, addr, d.Dialer.Dial)
}

func (d *ContextDialer) DialTcpContext(ctx context.Context, addr string) (c Conn, err error) {
	return DialContext(ctx, "", addr, func(network, addr string) (c Conn, err error) {
		return d.Dialer.DialTcp(addr)
	})
}

func (d *ContextDialer) DialUdpContext(ctx context.Context, addr string) (c PacketConn, err error) {
	conn, err := DialContext(ctx, "", addr, func(network, addr string) (c Conn, err error) {
		return d.Dialer.DialUdp(addr)
	})
	if err != nil {
		return nil, err
	}
	return conn.(PacketConn), nil
}
