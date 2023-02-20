package proto

import (
	"errors"
	"fmt"
	"github.com/mzz2017/softwind/ciphers"
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

func (d *Dialer) protocolFromInnerConn(conn netproxy.Conn, addr socks.Addr) (proto IProtocol, err error) {
	proto = NewProtocol(d.Protocol)
	if proto == nil {
		return nil, errors.New("unsupported protocol type: " + d.Protocol)
	}
	proto.SetData(proto.GetData())
	switch c := conn.(type) {
	case interface{ Cipher() *ciphers.StreamCipher }:
		iv, err := c.Cipher().InitEncrypt()
		if err != nil {
			return nil, err
		}
		key := c.Cipher().Key()
		if key == nil {
			return nil, fmt.Errorf("ss conn did not init Key")
		}
		proto.InitWithServerInfo(&ServerInfo{
			Param:    d.ProtocolParam,
			TcpMss:   1460,
			IV:       iv,
			Key:      key,
			AddrLen:  len(addr),
			Overhead: proto.GetOverhead() + d.ObfsOverhead,
		})
		return proto, nil
	default:
		return nil, fmt.Errorf("unsupported conn: %T", conn)
	}
}

func (d *Dialer) Dial(network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		return d.DialTcp(addr)
	case "udp":
		return d.DialUdp(addr)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) DialTcp(address string) (conn netproxy.Conn, err error) {
	addr, err := socks.ParseAddr(address)
	if err != nil {
		return nil, err
	}

	switch nextDialer := d.NextDialer.(type) {
	case *shadowsocks_stream.Dialer:
		conn, err = nextDialer.DialTcpTransport()
		if err != nil {
			return nil, err
		}
		proto, err := d.protocolFromInnerConn(conn, addr)
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
	addr, err := socks.ParseAddr(address)
	if err != nil {
		return nil, err
	}

	switch nextDialer := d.NextDialer.(type) {
	case *shadowsocks_stream.Dialer:
		c, err := nextDialer.DialUdpTransport()
		if err != nil {
			return nil, err
		}

		proto, err := d.protocolFromInnerConn(c, addr)
		if err != nil {
			return nil, err
		}

		return NewPacketConn(c, proto, address)
	default:
		return nil, fmt.Errorf("unsupported inner dialer: %T", nextDialer)
	}
}
