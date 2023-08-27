package tuic

import (
	"container/list"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/softwind/netproxy"
	"github.com/daeuniverse/softwind/pkg/fastrand"
	"github.com/daeuniverse/softwind/pool"
	"github.com/daeuniverse/softwind/protocol"
	"github.com/daeuniverse/softwind/protocol/tuic/common"
	"github.com/mzz2017/quic-go"
)

type Packets struct {
	mu       sync.Mutex
	list     *list.List
	nonEmpty chan struct{}
	closed   bool
}

func NewPackets() *Packets {
	return &Packets{
		list:     list.New().Init(),
		nonEmpty: make(chan struct{}),
	}
}

func (p *Packets) PushBack(packet *Packet) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.list.PushBack(packet)
	select {
	case <-p.nonEmpty:
	default:
		close(p.nonEmpty)
	}
}

func (p *Packets) PopFrontBlock() (packet *Packet, closed bool) {
	<-p.nonEmpty
	if p.closed {
		return nil, true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	packet = p.list.Remove(p.list.Front()).(*Packet)
	if p.list.Len() == 0 {
		p.setEmpty()
	}
	return packet, false
}

func (p *Packets) setEmpty() {
	p.nonEmpty = make(chan struct{})
}

func (p *Packets) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	select {
	case <-p.nonEmpty:
	default:
		close(p.nonEmpty)
	}
	return nil
}

type quicStreamPacketConn struct {
	mu sync.Mutex

	target string

	connId          uint16
	quicConn        quic.Connection
	incomingPackets *Packets

	udpRelayMode          common.UdpRelayMode
	maxUdpRelayPacketSize int

	deferQuicConnFn func(quicConn quic.Connection, err error)
	closeDeferFn    func()

	closeOnce sync.Once
	closeErr  error
	closed    bool

	// TODO: multiple defraggers for different PKT_ID
	deFraggers sync.Map

	muTimer       sync.Mutex
	deadlineTimer *time.Timer
}

func (q *quicStreamPacketConn) Close() error {
	q.closeOnce.Do(func() {
		q.closed = true
		q.closeErr = q.close()
	})
	return q.closeErr
}

func (q *quicStreamPacketConn) close() (err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closeDeferFn != nil {
		defer q.closeDeferFn()
	}
	if q.deferQuicConnFn != nil {
		defer func() {
			q.deferQuicConnFn(q.quicConn, err)
		}()
	}
	if q.incomingPackets != nil {
		q.incomingPackets = nil

		buf := pool.GetBuffer()
		defer buf.Put()
		err = NewDissociate(q.connId, Ver5).WriteTo(buf)
		if err != nil {
			return
		}
		var stream quic.SendStream
		stream, err = q.quicConn.OpenUniStream()
		if err != nil {
			return
		}
		_, err = buf.WriteTo(stream)
		if err != nil {
			return
		}
		err = stream.Close()
		if err != nil {
			return
		}
	}
	return
}

func (q *quicStreamPacketConn) SetDeadline(t time.Time) error {
	q.muTimer.Lock()
	defer q.muTimer.Unlock()
	dur := time.Until(t)
	if q.deadlineTimer != nil {
		q.deadlineTimer.Reset(dur)
	} else {
		q.deadlineTimer = time.AfterFunc(dur, func() {
			q.muTimer.Lock()
			defer q.muTimer.Unlock()
			q.Close()
			q.deadlineTimer = nil
		})
	}
	return nil
}

func (q *quicStreamPacketConn) SetReadDeadline(t time.Time) error {
	// FIXME: Single direction.
	return q.SetDeadline(t)
}

func (q *quicStreamPacketConn) SetWriteDeadline(t time.Time) error {
	// FIXME: Single direction.
	return q.SetDeadline(t)
}

func (q *quicStreamPacketConn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.incomingPackets != nil {
		for {
			packet, closed := q.incomingPackets.PopFrontBlock()
			if closed {
				err = net.ErrClosed
				return
			}
			_d, _ := q.deFraggers.LoadOrStore(packet.PKT_ID, &deFragger{})
			d := _d.(*deFragger)
			var assembled bool
			// Feed packet into this deFragger.
			// Return if this PKT_ID is ready and assembled.
			if n, addr, assembled = d.Feed(packet, p); assembled {
				q.deFraggers.Delete(packet.PKT_ID)
				return
			} else {
				// FIXME: Timeout to clean deFraggers.
			}
		}
	} else {
		err = net.ErrClosed
	}
	return
}

func (q *quicStreamPacketConn) WriteTo(p []byte, addr string) (n int, err error) {
	if len(p) > 0xffff { // uint16 max
		return 0, quic.ErrMessageTooLarge(0xffff)
	}
	if q.closed {
		return 0, net.ErrClosed
	}
	if q.deferQuicConnFn != nil {
		defer func() {
			q.deferQuicConnFn(q.quicConn, err)
		}()
	}
	buf := pool.GetBuffer()
	defer buf.Put()
	mdata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return 0, err
	}
	address := NewAddress(&mdata)
	pktId := uint16(fastrand.Uint32())
	packet := NewPacket(q.connId, pktId, 1, 0, uint16(len(p)), address, p, Ver5)
	switch q.udpRelayMode {
	case common.QUIC:
		err = packet.WriteTo(buf)
		if err != nil {
			return
		}
		var stream quic.SendStream
		stream, err = q.quicConn.OpenUniStream()
		if err != nil {
			return
		}
		defer stream.Close()
		_, err = buf.WriteTo(stream)
		if err != nil {
			return
		}
	default: // native
		if len(p) > q.maxUdpRelayPacketSize {
			err = fragWriteNative(q.quicConn, packet, buf, q.maxUdpRelayPacketSize)
			if err != nil {
				return
			}
		} else {
			err = packet.WriteTo(buf)
			if err != nil {
				return
			}
			data := buf.Bytes()
			err = q.quicConn.SendMessage(data)
		}
		var tooLarge quic.ErrMessageTooLarge
		if errors.As(err, &tooLarge) {
			err = fragWriteNative(q.quicConn, packet, buf, int(tooLarge)-PacketOverHead)
		}
		if err != nil {
			return
		}
	}
	n = len(p)

	return
}

func (q *quicStreamPacketConn) LocalAddr() net.Addr {
	return q.quicConn.LocalAddr()
}

func (conn *quicStreamPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = conn.ReadFrom(b)
	return n, err
}

func (conn *quicStreamPacketConn) Write(b []byte) (n int, err error) {
	return conn.WriteTo(b, conn.target)
}

var _ netproxy.PacketConn = (*quicStreamPacketConn)(nil)
