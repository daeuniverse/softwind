package juicity

import (
	"context"
	"fmt"
	"math"
	"net"
	"strconv"
	"time"

	"github.com/daeuniverse/softwind/netproxy"
	"github.com/daeuniverse/softwind/protocol"
	"github.com/daeuniverse/softwind/protocol/shadowsocks"
	"github.com/daeuniverse/softwind/protocol/trojanc"
	"github.com/daeuniverse/softwind/protocol/tuic/common"
	"github.com/google/uuid"
	"github.com/mzz2017/quic-go"
)

func init() {
	protocol.Register("juicity", NewDialer)
}

type Dialer struct {
	clientRing *clientRing

	proxyAddress string
	nextDialer   netproxy.Dialer
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
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
	if reservedStreamsCapability > 5 {
		reservedStreamsCapability = 5
	}
	return &Dialer{
		clientRing: newClientRing(func(capabilityCallback func(n int64)) *clientImpl {
			ctx, cancel := context.WithCancel(context.Background())
			return &clientImpl{
				ClientOption: &ClientOption{
					TlsConfig: header.TlsConfig,
					QuicConfig: &quic.Config{
						InitialStreamReceiveWindow:     common.InitialStreamReceiveWindow,
						MaxStreamReceiveWindow:         common.MaxStreamReceiveWindow,
						InitialConnectionReceiveWindow: common.InitialConnectionReceiveWindow,
						MaxConnectionReceiveWindow:     common.MaxConnectionReceiveWindow,
						KeepAlivePeriod:                5 * time.Second,
						DisablePathMTUDiscovery:        false,
						EnableDatagrams:                false,
						HandshakeIdleTimeout:           8 * time.Second,
						CapabilityCallback:             capabilityCallback,
					},
					Uuid:                 id,
					Password:             header.Password,
					CongestionController: header.Feature1,
					CWND:                 10,
					Ctx:                  ctx,
					Cancel:               cancel,
					UnderlayAuth:         make(chan *UnderlayAuth, 64),
				},
			}
		}, reservedStreamsCapability),
		proxyAddress: header.ProxyAddress,
		nextDialer:   nextDialer,
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

func (d *Dialer) dialFuncFactory(udpNetwork string, rAddr net.Addr) common.DialFunc {
	return func(ctx context.Context, dialer netproxy.Dialer) (transport *quic.Transport, addr net.Addr, err error) {
		conn, err := dialer.Dial(udpNetwork, d.proxyAddress)
		if err != nil {
			return nil, nil, err
		}
		pc := &netproxy.FakeNetPacketConn{
			PacketConn: conn.(netproxy.PacketConn),
			LAddr:      net.UDPAddrFromAddrPort(common.GetUniqueFakeAddrPort()),
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
		mdata.IsClient = true
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
		}
		if magicNetwork.Network == "udp" {
			switch mdata.Port {
			case 443, 8443, 5201:
				iv, psk, err := d.clientRing.DialAuth(&trojanc.Metadata{
					Metadata: mdata,
					Network:  magicNetwork.Network,
				}, d.nextDialer, d.dialFuncFactory(udpNetwork, proxyAddr))
				if err != nil {
					return nil, err
				}
				key, err := underlayKey(psk)
				if err != nil {
					return nil, err
				}
				innerAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(mdata.Hostname, strconv.Itoa(int(mdata.Port))))
				if err != nil {
					return nil, err
				}
				transport, _, err := d.dialFuncFactory(udpNetwork, proxyAddr)(context.TODO(), d.nextDialer)
				if err != nil {
					return nil, err
				}
				return &TransportPacketConn{
					Transport: transport,
					proxyAddr: proxyAddr,
					tgt:       innerAddr.AddrPort(),
					key:       key,
					firstIv:   iv,
				}, nil
			}
		}
		conn, err := d.clientRing.Dial(&trojanc.Metadata{
			Metadata: mdata,
			Network:  magicNetwork.Network,
		}, d.nextDialer,
			d.dialFuncFactory(udpNetwork, proxyAddr),
		)
		if err != nil {
			return nil, err
		}
		if magicNetwork.Network == "tcp" {
			time.AfterFunc(100*time.Millisecond, func() {
				// avoid the situation where the server sends messages first
				if _, err = conn.Write(nil); err != nil {
					return
				}
			})
			return conn, nil
		} else {
			return &PacketConn{
				Conn: conn,
			}, nil
		}

	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}
}

func underlayKey(psk []byte) (key *shadowsocks.Key, err error) {
	return &shadowsocks.Key{
		CipherConf: CipherConf,
		MasterKey:  psk,
	}, nil
}

func (d *Dialer) DialCmdMsg(cmd protocol.MetadataCmd) (c netproxy.Conn, err error) {
	proxyAddr, err := net.ResolveUDPAddr("udp", d.proxyAddress)
	if err != nil {
		return nil, err
	}
	conn, err := d.clientRing.Dial(&trojanc.Metadata{
		Metadata: protocol.Metadata{
			Type:     protocol.MetadataTypeMsg,
			Cmd:      cmd,
			IsClient: true,
		},
	}, d.nextDialer,
		d.dialFuncFactory("udp", proxyAddr),
	)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
