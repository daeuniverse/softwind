package netproxy

import (
	"context"
)

// A Dialer is a means to establish a connection.
// Custom dialers should also implement ContextDialer.
type Dialer interface {
	DialTcp(addr string) (c Conn, err error)
	DialUdp(addr string) (c PacketConn, err error)
}

type TcpDialer interface {
	DialTcp(addr string) (c Conn, err error)
}

type ContextDialer struct {
	Dialer Dialer
}

func (d *ContextDialer) DialTcpContext(ctx context.Context, addr string) (c Conn, err error) {
	var done = make(chan struct{})
	go func() {
		c, err = d.Dialer.DialTcp(addr)
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
func (d *ContextDialer) DialUdpContext(ctx context.Context, addr string) (c PacketConn, err error) {
	var done = make(chan struct{})
	go func() {
		c, err = d.Dialer.DialUdp(addr)
		if err != nil {
			close(done)
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

func (d *ContextDialer) DialTcp(addr string) (c Conn, err error) {
	return d.Dialer.DialTcp(addr)
}

func (d *ContextDialer) DialUdp(addr string) (c PacketConn, err error) {
	return d.Dialer.DialUdp(addr)
}
