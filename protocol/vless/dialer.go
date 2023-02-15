package trojanc

import (
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/protocol"
	"github.com/mzz2017/softwind/protocol/vmess"
	"net"
)

func init() {
	protocol.Register("vless", NewDialer)
}

type Dialer struct {
	proxyAddress string
	nextDialer   netproxy.Dialer
	metadata     protocol.Metadata
	key          []byte
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}
	//log.Trace("vless.NewDialer: metadata: %v, password: %v", metadata, password)
	id, err := Password2Key(header.Password)
	if err != nil {
		return nil, err
	}
	return &Dialer{
		proxyAddress: header.ProxyAddress,
		nextDialer:   nextDialer,
		metadata:     metadata,
		key:          id,
	}, nil
}

func (d *Dialer) DialTcp(addr string) (c netproxy.Conn, err error) {
	return d.Dial("tcp", addr)
}

func (d *Dialer) DialUdp(addr string) (c netproxy.PacketConn, err error) {
	return d.Dial("udp", addr)
}

func (d *Dialer) Dial(network string, addr string) (c netproxy.FullConn, err error) {
	switch network {
	case "tcp", "udp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.IsClient = d.metadata.IsClient

		conn, err := d.nextDialer.DialTcp(d.proxyAddress)
		if err != nil {
			return nil, err
		}

		return NewConn(conn, vmess.Metadata{
			Metadata: mdata,
			Network:  network,
		}, d.key)
	default:
		return nil, net.UnknownNetworkError(network)
	}
}
