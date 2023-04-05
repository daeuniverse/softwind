package trojanc

import (
	"encoding/binary"
	"github.com/mzz2017/softwind/pool"
	"github.com/mzz2017/softwind/protocol"
	"io"
	"net/netip"
)

func (c *Conn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	buf := pool.Get(1)
	defer pool.Put(buf)
	if _, err = io.ReadFull(c, buf); err != nil {
		return 0, netip.AddrPort{}, err
	}
	m := Metadata{Metadata: protocol.Metadata{Type: ParseMetadataType(buf[0])}}
	buf = pool.Get(m.Len())
	buf[0] = MetadataTypeToByte(m.Type)
	defer pool.Put(buf)
	if _, err = io.ReadFull(c, buf[1:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	if _, err = m.Unpack(buf); err != nil {
		return 0, netip.AddrPort{}, err
	}

	if addr, err = m.AddrPort(); err != nil {
		return 0, netip.AddrPort{}, err
	}

	if _, err = io.ReadFull(c, buf[:2]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	length := binary.BigEndian.Uint16(buf)
	buf = pool.Get(2 + int(length))
	defer pool.Put(buf)
	if _, err = io.ReadFull(c, buf); err != nil {
		return 0, netip.AddrPort{}, err
	}
	copy(p, buf[2:])
	return int(length), addr, nil
}

func (c *Conn) WriteTo(p []byte, addr string) (n int, err error) {
	_metadata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return 0, err
	}
	metadata := Metadata{
		Metadata: _metadata,
		Network:  "udp",
	}
	buf := pool.Get(metadata.Len() + 4 + len(p))
	defer pool.Put(buf)
	SealUDP(metadata, buf, p)
	_, err = c.Write(buf)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func SealUDP(metadata Metadata, dst []byte, data []byte) []byte {
	n := metadata.Len()
	// copy first to allow overlap
	copy(dst[n+4:], data)
	metadata.PackTo(dst)
	binary.BigEndian.PutUint16(dst[n:], uint16(len(data)))
	copy(dst[n+2:], CRLF)
	return dst[:n+4+len(data)]
}
