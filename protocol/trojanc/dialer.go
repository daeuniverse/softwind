package trojanc

import (
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/protocol"
	"net"
)

func init() {
	protocol.Register("trojanc", NewDialer)
}

type Dialer struct {
	proxyAddress string
	nextDialer   netproxy.Dialer
	metadata     protocol.Metadata
	password     string
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}
	//log.Trace("trojanc.NewDialer: metadata: %v, password: %v", metadata, password)
	return &Dialer{
		proxyAddress: header.ProxyAddress,
		nextDialer:   nextDialer,
		metadata:     metadata,
		password:     header.Password,
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

		return NewConn(conn, Metadata{
			Metadata: mdata,
			Network:  network,
		}, d.password)
	default:
		return nil, net.UnknownNetworkError(network)
	}
}
