package juicity

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/daeuniverse/softwind/pool"
	"github.com/daeuniverse/softwind/protocol"
	"github.com/daeuniverse/softwind/protocol/trojanc"
)

type PacketConn struct {
	*Conn
	domainIpMapping sync.Map
}

func (c *PacketConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, net.JoinHostPort(c.Conn.Metadata.Hostname, strconv.Itoa(int(c.Conn.Metadata.Port))))
}

func (c *PacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return n, err
}

func (c *PacketConn) ReadFrom(p []byte) (n int, addrPort netip.AddrPort, err error) {
	m := trojanc.Metadata{}
	if _, err = m.Unpack(c.Conn); err != nil {
		return 0, netip.AddrPort{}, err
	}
	if m.Type == protocol.MetadataTypeDomain {
		if _addr, ok := c.domainIpMapping.Load(m.Hostname); ok {
			addrPort = netip.AddrPortFrom(_addr.(netip.Addr), m.Port)
		} else {
			uAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(m.Hostname, strconv.Itoa(int(m.Port))))
			if err != nil {
				return 0, netip.AddrPort{}, err
			}
			addrPort = uAddr.AddrPort()
			if _addr, ok = c.domainIpMapping.LoadOrStore(m.Hostname, addrPort.Addr()); ok {
				addrPort = netip.AddrPortFrom(_addr.(netip.Addr), m.Port)
			}
		}
	} else {
		if addrPort, err = m.AddrPort(); err != nil {
			return 0, netip.AddrPort{}, fmt.Errorf("ReadFrom AddrPort: %w", err)
		}
	}

	buf := pool.Get(2)
	defer buf.Put()
	if _, err = io.ReadFull(c.Conn, buf[:2]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	length := int(binary.BigEndian.Uint16(buf))
	if length <= len(p) {
		if n, err = io.ReadFull(c.Conn, p[:length]); err != nil {
			return 0, netip.AddrPort{}, err
		}
		return n, addrPort, nil
	} else {
		if n, err = io.ReadFull(c.Conn, p); err != nil {
			return 0, netip.AddrPort{}, err
		}
		_, _ = io.CopyN(io.Discard, c.Conn, int64(length-len(p)))
		return n, addrPort, nil
	}
}

func (c *PacketConn) WriteTo(p []byte, addr string) (n int, err error) {
	_metadata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return 0, err
	}
	metadata := trojanc.Metadata{
		Metadata: _metadata,
		Network:  "udp",
	}
	buf := pool.Get(metadata.Len() + 2 + len(p))
	defer pool.Put(buf)
	SealUDP(metadata, buf, p)
	_, err = c.Conn.Write(buf)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *PacketConn) Close() error {
	return c.Conn.Close()
}

func SealUDP(metadata trojanc.Metadata, dst []byte, data []byte) []byte {
	n := metadata.Len()
	// copy first to allow overlap
	copy(dst[n+2:], data)
	metadata.PackTo(dst)
	binary.BigEndian.PutUint16(dst[n:], uint16(len(data)))
	return dst[:n+2+len(data)]
}
