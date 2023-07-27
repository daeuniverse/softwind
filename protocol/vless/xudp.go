package vless

import (
	"encoding/binary"
	"errors"
	"hash/maphash"
	"io"
	"net"
	"net/netip"
	"unsafe"

	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/pool"
	"github.com/mzz2017/softwind/protocol/infra/socks"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
)

var globalSeed = maphash.MakeSeed()

const (
	MuxStatusNew       = 1
	MuxStatusKeep      = 2
	MuxStatusEnd       = 3
	MuxStatusKeepAlive = 4
	MuxOptionData      = 1
	MuxOptionError     = 2
	MuxNetworkTCP      = 1
	MuxNetworkUDP      = 2
)

func GlobalID(material string) (id [8]byte) {
	*(*uint64)(unsafe.Pointer(&id[0])) = maphash.String(globalSeed, material)
	return
}

type XUDPConn struct {
	netproxy.Conn
	destination    socks.Addr
	requestWritten bool
}

func NewXUDPConn(conn netproxy.Conn, destination socks.Addr) *XUDPConn {
	return &XUDPConn{
		Conn:        conn,
		destination: destination,
	}
}

func (c *XUDPConn) Read(p []byte) (n int, err error) {
	n, _, err = c.ReadFrom(p)
	return
}

func (c *XUDPConn) Write(p []byte) (n int, err error) {
	return c.WriteTo(p, c.destination)
}

func (c *XUDPConn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	buffer := buf.With(p)
	var destination socks.Addr
	destination, err = c.ReadPacket(buffer)
	if err != nil {
		return
	}
	destination.String()
	n = buffer.Len()
	return
}

func (c *XUDPConn) ReadPacket() (destination socks.Addr, err error) {
	buf := pool.Get(6)
	defer buf.Put()
	_, err = io.ReadFull(c.Conn, buf)
	if err != nil {
		return
	}
	length := binary.BigEndian.Uint16(buf)
	header := buf[2:]
	switch header[2] {
	case MuxStatusNew:
		return socks.Addr{}, errors.New("unexpected frame new")
	case MuxStatusKeep:
		if length != 4 {
			buf := pool.Get(int(length) - 2)
			defer buf.Put()
			_, err = io.ReadFull(c.Conn, buf)
			if err != nil {
				return
			}
			buffer.Advance(1)
			destination, err = AddressSerializer.ReadAddrPort(buffer)
			if err != nil {
				return
			}
			destination = destination.Unwrap()
		} else {
			_, err = buffer.ReadFullFrom(c.Conn, 2)
			if err != nil {
				return
			}
			destination = c.destination
		}
	case MuxStatusEnd:
		return socks.Addr{}, io.EOF
	case MuxStatusKeepAlive:
	default:
		return socks.Addr{}, E.New("unexpected frame: ", buffer.Byte(2))
	}
	// option error
	if header[3]&2 == 2 {
		return socks.Addr{}, E.Cause(net.ErrClosed, "remote closed")
	}
	// option data
	if header[3]&1 != 1 {
		buffer.Resize(start, 0)
		return c.ReadPacket(buffer)
	} else {
		err = binary.Read(buffer, binary.BigEndian, &length)
		if err != nil {
			return
		}
		buffer.Resize(start, 0)
		_, err = buffer.ReadFullFrom(c.Conn, int(length))
		return
	}
}

func (c *XUDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return bufio.WritePacketBuffer(c, buf.As(p), socks.AddrFromNet(addr))
}

func (c *XUDPConn) frontHeadroom(addrLen int) int {
	if !c.requestWritten {
		var headerLen int
		headerLen += 2 // frame len
		headerLen += 5 // frame header
		headerLen += addrLen
		headerLen += 2 // payload len
		return headerLen
	} else {
		return 7 + addrLen + 2
	}
}

func (c *XUDPConn) WritePacket(buffer *buf.Buffer, destination socks.Addr) error {
	dataLen := buffer.Len()
	addrLen := socks.AddrSerializer.AddrPortLen(destination)
	if !c.requestWritten {
		header := buf.With(buffer.ExtendHeader(c.frontHeadroom(addrLen)))
		common.Must(
			binary.Write(header, binary.BigEndian, uint16(5+addrLen)),
			header.WriteByte(0),
			header.WriteByte(0),
			header.WriteByte(1), // frame type new
			header.WriteByte(1), // option data
			header.WriteByte(MuxNetworkUDP),
			AddressSerializer.WriteAddrPort(header, destination),
			binary.Write(header, binary.BigEndian, uint16(dataLen)),
		)
		c.requestWritten = true
	} else {
		header := buffer.ExtendHeader(c.frontHeadroom(addrLen))
		binary.BigEndian.PutUint16(header, uint16(5+addrLen))
		header[2] = 0
		header[3] = 0
		header[4] = 2 // frame keep
		header[5] = 1 // option data
		header[6] = MuxNetworkUDP
		err := AddressSerializer.WriteAddrPort(buf.With(header[7:]), destination)
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint16(header[7+addrLen:], uint16(dataLen))
	}
	return c.writer.WriteBuffer(buffer)
}

func (c *XUDPConn) NeedHandshake() bool {
	return !c.requestWritten
}

func (c *XUDPConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *XUDPConn) Upstream() any {
	return c.Conn
}
