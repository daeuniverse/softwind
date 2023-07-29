package direct

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"syscall"

	"github.com/mzz2017/softwind/netproxy"
)

var fwmarkIoctl int

func init() {
	switch runtime.GOOS {
	case "linux", "android":
		fwmarkIoctl = 36 /* unix.SO_MARK */
	case "freebsd":
		fwmarkIoctl = 0x1015 /* unix.SO_USER_COOKIE */
	case "openbsd":
		fwmarkIoctl = 0x1021 /* unix.SO_RTABLE */
	}
}

var SymmetricDirect = newDirectDialer(false)
var FullconeDirect = newDirectDialer(true)

type directDialer struct {
	netproxy.Dialer
	fullCone bool
}

func newDirectDialer(fullCone bool) netproxy.Dialer {
	return &directDialer{
		fullCone: fullCone,
	}
}

func (d *directDialer) dialUdp(addr string, mark int) (c netproxy.PacketConn, err error) {
	if mark == 0 {
		if d.fullCone {
			conn, err := net.ListenUDP("udp", nil)
			if err != nil {
				return nil, err
			}
			return &directPacketConn{UDPConn: conn, FullCone: true, dialTgt: addr}, nil
		} else {
			conn, err := net.Dial("udp", addr)
			if err != nil {
				return nil, err
			}
			return &directPacketConn{UDPConn: conn.(*net.UDPConn), FullCone: false, dialTgt: addr}, nil
		}

	} else {
		var conn *net.UDPConn
		if d.fullCone {
			conn, err = net.ListenUDP("udp", nil)
			if err != nil {
				return nil, err
			}
		} else {
			d := net.Dialer{
				Control: func(network, address string, c syscall.RawConn) error {
					return netproxy.SoMarkControl(c, mark)
				},
			}
			c, err := d.Dial("udp", addr)
			if err != nil {
				return nil, err
			}
			conn = c.(*net.UDPConn)
		}
		f, err := conn.File()
		if err != nil {
			return nil, err
		}
		defer f.Close()

		if err = netproxy.SoMark(int(f.Fd()), mark); err != nil {
			return nil, err
		}
		return &directPacketConn{UDPConn: conn, FullCone: d.fullCone, dialTgt: addr, resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Control: func(network, address string, c syscall.RawConn) error {
						return netproxy.SoMarkControl(c, mark)
					},
				}
				return d.DialContext(ctx, network, address)
			},
		}}, nil
	}
}

func (d *directDialer) dialTcp(addr string, mark int) (c netproxy.Conn, err error) {
	if mark == 0 {
		return net.Dial("tcp", addr)
	} else {
		dialer := net.Dialer{
			Control: func(network, address string, c syscall.RawConn) error {
				return netproxy.SoMarkControl(c, mark)
			},
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Control: func(network, address string, c syscall.RawConn) error {
							return netproxy.SoMarkControl(c, mark)
						},
					}
					return d.DialContext(ctx, network, address)
				},
			},
		}
		return dialer.Dial("tcp", addr)
	}
}

func (d *directDialer) Dial(network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		return d.dialTcp(addr, int(magicNetwork.Mark))
	case "udp":
		return d.dialUdp(addr, int(magicNetwork.Mark))
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
