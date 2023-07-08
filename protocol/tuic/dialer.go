package tuic

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mzz2017/quic-go"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/protocol"
	"github.com/mzz2017/softwind/protocol/tuic/common"
)

func init() {
	protocol.Register("tuic", NewDialer)
}

type Dialer struct {
	clientRing *clientRing

	proxyAddress string
	nextDialer   netproxy.Dialer
	metadata     protocol.Metadata
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}

	id, err := uuid.Parse(header.User)
	if err != nil {
		return nil, fmt.Errorf("parse UUID: %w", err)
	}
	// ensure server's incoming stream can handle correctly, increase to 1.1x
	maxOpenIncomingStreams := int64(100)
	quicMaxOpenIncomingStreams := int64(maxOpenIncomingStreams)
	quicMaxOpenIncomingStreams = quicMaxOpenIncomingStreams + int64(math.Ceil(float64(quicMaxOpenIncomingStreams)/10.0))
	reservedStreamsCapability := maxOpenIncomingStreams / 5
	if reservedStreamsCapability < 1 {
		reservedStreamsCapability = 1
	}
	maxDatagramFrameSize := 1400
	udpRelayMode := common.NATIVE
	if header.Flags&protocol.Flags_Tuic_UdpRelayModeQuic > 0 {
		// FIXME: QUIC has severe performance problems.
		// udpRelayMode = common.QUIC
	}
	return &Dialer{
		clientRing: newClientRing(func(capabilityCallback func(n int64)) *clientImpl {
			return &clientImpl{
				ClientOption: &ClientOption{
					TlsConfig: header.TlsConfig,
					QuicConfig: &quic.Config{
						InitialStreamReceiveWindow:     common.InitialStreamReceiveWindow,
						MaxStreamReceiveWindow:         common.MaxStreamReceiveWindow,
						InitialConnectionReceiveWindow: common.InitialConnectionReceiveWindow,
						MaxConnectionReceiveWindow:     common.MaxConnectionReceiveWindow,
						MaxIncomingStreams:             quicMaxOpenIncomingStreams,
						MaxIncomingUniStreams:          quicMaxOpenIncomingStreams,
						KeepAlivePeriod:                3 * time.Second,
						DisablePathMTUDiscovery:        false,
						MaxDatagramFrameSize:           int64(maxDatagramFrameSize + PacketOverHead),
						EnableDatagrams:                true,
						HandshakeIdleTimeout:           8 * time.Second,
						CapabilityCallback:             capabilityCallback,
					},
					Uuid:                  id,
					Password:              header.Password,
					UdpRelayMode:          udpRelayMode,
					CongestionController:  header.Feature1,
					ReduceRtt:             false,
					CWND:                  10,
					MaxUdpRelayPacketSize: maxDatagramFrameSize,
				},
				udp: true,
			}
		}, reservedStreamsCapability),
		proxyAddress: header.ProxyAddress,
		nextDialer:   nextDialer,
		metadata:     metadata,
	}, nil
}

func (d *Dialer) DialTcp(addr string) (c netproxy.Conn, err error) {
	return d.Dial("tcp", addr)
}

func (d *Dialer) DialUdp(addr string) (c netproxy.PacketConn, err error) {
	pktConn, err := d.Dial("udp", addr)
	if err != nil {
		return nil, err
	}
	return pktConn.(netproxy.PacketConn), nil
}

var uniqueFakeAddrPort = struct {
	addr netip.Addr
	port uint16
	mu   sync.Mutex
}{
	addr: netip.MustParseAddr("::1"),
	mu:   sync.Mutex{},
}

func getUniqueFakeAddrPort() (fake netip.AddrPort) {
	uniqueFakeAddrPort.mu.Lock()
	if uniqueFakeAddrPort.port == 65535 {
		uniqueFakeAddrPort.addr = uniqueFakeAddrPort.addr.Next()
		uniqueFakeAddrPort.port = 0
	} else {
		uniqueFakeAddrPort.port++
	}
	fake = netip.AddrPortFrom(uniqueFakeAddrPort.addr, uniqueFakeAddrPort.port)
	uniqueFakeAddrPort.mu.Unlock()
	return fake
}

func (d *Dialer) dialFuncFactory(udpNetwork string, rAddr net.Addr) common.DialFunc {
	return func(ctx context.Context, dialer netproxy.Dialer) (transport *quic.Transport, addr net.Addr, err error) {
		conn, err := dialer.Dial(udpNetwork, d.proxyAddress)
		if err != nil {
			return nil, nil, err
		}
		pc := &netproxy.FakeNetPacketConn{
			PacketConn: conn.(netproxy.PacketConn),
			LAddr:      net.UDPAddrFromAddrPort(getUniqueFakeAddrPort()),
			RAddr:      rAddr,
		}
		transport = &quic.Transport{Conn: pc}
		transport.SetCreatedConn(true)
		transport.SetSingleUse(true)
		return transport, rAddr, nil
	}
}

func (d *Dialer) Dial(network string, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp", "udp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.IsClient = d.metadata.IsClient
		proxyAddr, err := net.ResolveUDPAddr("udp", d.proxyAddress)
		if err != nil {
			return nil, err
		}
		udpNetwork := network
		if magicNetwork.Network == "tcp" {
			udpNetwork = netproxy.MagicNetwork{
				Network: "udp",
				Mark:    magicNetwork.Mark,
			}.Encode()
			tcpConn, err := d.clientRing.DialContextWithDialer(context.TODO(), &mdata, d.nextDialer,
				d.dialFuncFactory(udpNetwork, proxyAddr),
			)
			if err != nil {
				return nil, err
			}
			return tcpConn, nil
		} else {
			udpConn, err := d.clientRing.ListenPacketWithDialer(context.TODO(), &mdata, d.nextDialer,
				d.dialFuncFactory(udpNetwork, proxyAddr),
			)
			if err != nil {
				return nil, err
			}
			udpConn.(*quicStreamPacketConn).target = addr
			return udpConn, nil
		}

	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}
}