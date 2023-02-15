package vmess

import (
	"github.com/google/uuid"
	"github.com/mzz2017/softwind/common"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/protocol"
	"github.com/mzz2017/softwind/transport/grpc"
	"net"
)

func init() {
	protocol.Register("vmess", NewDialerFactory(protocol.ProtocolVMessTCP))
	protocol.Register("vmess+tls+grpc", NewDialerFactory(protocol.ProtocolVMessTlsGrpc))
}

type Dialer struct {
	protocol        protocol.Protocol
	proxyAddress    string
	proxySNI        string
	grpcServiceName string
	nextDialer      netproxy.Dialer
	metadata        protocol.Metadata
	key             []byte
	shouldFullCone  bool
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}
	cipher, _ := ParseCipherFromSecurity(Cipher(header.Cipher).ToSecurity())
	metadata.Cipher = string(cipher)

	// UUID mapping
	if l := len([]byte(header.Password)); l < 32 || l > 36 {
		header.Password = common.StringToUUID5(header.Password)
	}

	id, err := uuid.Parse(header.Password)
	if err != nil {
		return nil, err
	}
	//log.Trace("vmess.NewDialer: metadata: %v, password: %v", metadata, password)
	return &Dialer{
		proxyAddress:    header.ProxyAddress,
		proxySNI:        header.SNI,
		grpcServiceName: header.GrpcServiceName,
		nextDialer:      nextDialer,
		metadata:        metadata,
		key:             NewID(id).CmdKey(),
		shouldFullCone:  header.ShouldFullCone,
	}, nil
}

func NewDialerFactory(proto protocol.Protocol) func(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	return func(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
		d, err := NewDialer(nextDialer, header)
		if err != nil {
			return nil, err
		}
		dd := d.(*Dialer)
		dd.protocol = proto
		return dd, nil
	}
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
		mdata.Cipher = d.metadata.Cipher
		mdata.IsClient = d.metadata.IsClient
		if d.shouldFullCone && network == "udp" {
			mdata.Hostname = SeqPacketMagicAddress
			mdata.Type = protocol.MetadataTypeDomain
		}

		if d.protocol == protocol.ProtocolVMessTlsGrpc {
			d.nextDialer = &grpc.Dialer{
				NextDialer:  &netproxy.ContextDialer{Dialer: d.nextDialer},
				ServiceName: d.grpcServiceName,
				ServerName:  d.proxySNI,
			}
		}
		conn, err := d.nextDialer.DialTcp(d.proxyAddress)
		if err != nil {
			return nil, err
		}

		return NewConn(conn, Metadata{
			Metadata: mdata,
			Network:  network,
		}, addr ,d.key)
	default:
		return nil, net.UnknownNetworkError(network)
	}
}
