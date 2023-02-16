package proto

import (
	"errors"
	"fmt"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/protocol/infra/socks"
	"github.com/mzz2017/softwind/protocol/shadowsocks_stream"
)

type Dialer struct {
	NextDialer    netproxy.Dialer
	Protocol      string
	ProtocolParam string
	ObfsOverhead  int
	protocolData  interface{}
}

func (d *Dialer) DialTcp(address string) (conn netproxy.Conn, err error) {
	addr, err := socks.ParseAddr(address)
	if err != nil {
		return nil, err
	}

	proto := NewProtocol(d.Protocol)
	if proto == nil {
		return nil, errors.New("unsupported protocol type: " + d.Protocol)
	}

	protocolServerInfo := &ServerInfo{
		Param:    d.ProtocolParam,
		TcpMss:   1460,
		Overhead: proto.GetOverhead() + d.ObfsOverhead,
	}
	proto.SetServerInfo(protocolServerInfo)

	switch nextDialer := d.NextDialer.(type) {
	case *shadowsocks_stream.Dialer:
		conn, err = nextDialer.DialTcpNoSendAddr(address)
		if err != nil {
			return nil, err
		}
		conn, err = NewConn(conn, proto)
		if err != nil {
			return nil, err
		}
		if _, err = conn.Write(addr); err != nil {
			return nil, fmt.Errorf("failed to write target: %w", err)
		}
		return conn, nil
	default:
		return nil, fmt.Errorf("unsupported next dialer: %T", d.NextDialer)
	}
}

func (d *Dialer) DialUdp(address string) (netproxy.PacketConn, error) {
	return nil, netproxy.UnsupportedTunnelTypeError
}
