package shadowsocks

import (
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/protocol"
)

func init() {
	protocol.Register("shadowsocks", NewDialer)
}

type Dialer struct {
	proxyAddress string
	nextDialer   netproxy.Dialer
	metadata     protocol.Metadata
	key          []byte
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	//log.Trace("shadowsocks.NewDialer: metadata: %v, password: %v", metadata, password)
	return &Dialer{
		proxyAddress: header.ProxyAddress,
		nextDialer:   nextDialer,
		metadata: protocol.Metadata{
			Cipher:   header.Cipher,
			IsClient: header.IsClient,
		},
		key: EVPBytesToKey(header.Password, CiphersConf[header.Cipher].KeyLen),
	}, nil
}

func (d *Dialer) DialTcp(addr string) (c netproxy.Conn, err error) {
	mdata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return nil, err
	}
	mdata.Cipher = d.metadata.Cipher
	mdata.IsClient = d.metadata.IsClient

	// Shadowsocks transfer TCP traffic via TCP tunnel.
	conn, err := d.nextDialer.DialTcp(d.proxyAddress)
	if err != nil {
		return nil, err
	}
	return NewTCPConn(conn, mdata, d.key, nil)
}

func (d *Dialer) DialUdp(addr string) (c netproxy.PacketConn, err error) {
	mdata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return nil, err
	}
	mdata.Cipher = d.metadata.Cipher
	mdata.IsClient = d.metadata.IsClient

	// Shadowsocks transfer UDP traffic via UDP tunnel.
	conn, err := d.nextDialer.DialUdp(d.proxyAddress)
	if err != nil {
		return nil, err
	}
	return NewUdpConn(conn.(netproxy.PacketConn), d.proxyAddress, mdata, d.key, nil)
}
