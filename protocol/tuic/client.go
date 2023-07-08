package tuic

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mzz2017/quic-go"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/pkg/fastrand"
	"github.com/mzz2017/softwind/pool"
	"github.com/mzz2017/softwind/protocol"
	"github.com/mzz2017/softwind/protocol/tuic/common"
)

type ClientOption struct {
	TlsConfig             *tls.Config
	QuicConfig            *quic.Config
	Uuid                  [16]byte
	Password              string
	UdpRelayMode          common.UdpRelayMode
	MaxUdpRelayPacketSize int
	CongestionController  string
	ReduceRtt             bool
	CWND                  int
}

type clientImpl struct {
	*ClientOption
	udp bool

	quicConn  quic.Connection
	connMutex sync.Mutex

	closed atomic.Bool

	udpIncomingPacketsMap sync.Map

	// only ready for PoolClient
	lastVisited atomic.Value

	onClose func()
}

func (t *clientImpl) LastVisited() time.Time {
	return t.lastVisited.Load().(time.Time)
}

func (t *clientImpl) SetLastVisited(last time.Time) {
	t.lastVisited.Store(last)
}

func (t *clientImpl) getQuicConn(ctx context.Context, dialer netproxy.Dialer, dialFn common.DialFunc) (quic.Connection, error) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.quicConn != nil {
		return t.quicConn, nil
	}
	transport, addr, err := dialFn(ctx, dialer)
	if err != nil {
		return nil, err
	}
	var quicConn quic.Connection
	if t.ReduceRtt {
		quicConn, err = transport.DialEarly(ctx, addr, t.TlsConfig, t.QuicConfig)
	} else {
		quicConn, err = transport.Dial(ctx, addr, t.TlsConfig, t.QuicConfig)
	}
	if err != nil {
		return nil, err
	}

	common.SetCongestionController(quicConn, t.CongestionController, t.CWND)

	go func() {
		_ = t.sendAuthentication(quicConn)
	}()

	if t.udp && t.UdpRelayMode == common.QUIC {
		go func() {
			_ = t.handleUniStream(quicConn)
		}()
	}
	go func() {
		_ = t.handleMessage(quicConn) // always handleMessage because tuicV5 using datagram to send the Heartbeat
	}()

	t.quicConn = quicConn
	return quicConn, nil
}

func (t *clientImpl) sendAuthentication(quicConn quic.Connection) (err error) {
	defer func() {
		t.deferQuicConn(quicConn, err)
	}()
	stream, err := quicConn.OpenUniStream()
	if err != nil {
		return err
	}
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
	token, err := GenToken(quicConn.ConnectionState(), t.Uuid, t.Password)
	if err != nil {
		return err
	}
	err = NewAuthenticate(t.Uuid, token).WriteTo(buf)
	if err != nil {
		return err
	}
	_, err = buf.WriteTo(stream)
	if err != nil {
		return err
	}
	err = stream.Close()
	if err != nil {
		return
	}
	return nil
}

func (t *clientImpl) handleUniStream(quicConn quic.Connection) (err error) {
	defer func() {
		t.deferQuicConn(quicConn, err)
	}()
	for {
		var stream quic.ReceiveStream
		stream, err = quicConn.AcceptUniStream(context.Background())
		if err != nil {
			return err
		}
		go func() (err error) {
			var assocId uint16
			defer func() {
				t.deferQuicConn(quicConn, err)
				if err != nil && assocId != 0 {
					if val, loaded := t.udpIncomingPacketsMap.LoadAndDelete(assocId); loaded {
						val.(*packets).Close()
					}
				}
				stream.CancelRead(0)
			}()
			reader := bufio.NewReader(stream)
			commandHead, err := ReadCommandHead(reader)
			if err != nil {
				return
			}
			switch commandHead.TYPE {
			case PacketType:
				var packet Packet
				packet, err = ReadPacketWithHead(commandHead, reader)
				if err != nil {
					return
				}
				if t.udp && t.UdpRelayMode == common.QUIC {
					assocId = packet.ASSOC_ID
					if val, ok := t.udpIncomingPacketsMap.Load(assocId); ok {
						packets := val.(*packets)
						packets.PushBack(&packet)
					}
				}
			}
			return
		}()
	}
}

func (t *clientImpl) handleMessage(quicConn quic.Connection) (err error) {
	defer func() {
		t.deferQuicConn(quicConn, err)
	}()
	for {
		var message []byte
		message, err = quicConn.ReceiveMessage()
		if err != nil {
			return err
		}
		go func() (err error) {
			var assocId uint16
			defer func() {
				t.deferQuicConn(quicConn, err)
				if err != nil && assocId != 0 {
					if val, loaded := t.udpIncomingPacketsMap.LoadAndDelete(assocId); loaded {
						val.(*packets).Close()
					}
				}
			}()
			reader := bytes.NewReader(message)
			commandHead, err := ReadCommandHead(reader)
			if err != nil {
				return
			}
			switch commandHead.TYPE {
			case PacketType:
				var packet Packet
				packet, err = ReadPacketWithHead(commandHead, reader)
				if err != nil {
					return
				}
				if t.udp && t.UdpRelayMode == common.NATIVE {
					assocId = packet.ASSOC_ID
					if val, ok := t.udpIncomingPacketsMap.Load(assocId); ok {
						incomingPackets := val.(*packets)
						incomingPackets.PushBack(&packet)
					}
				}
			case HeartbeatType:
				_, err = ReadHeartbeatWithHead(commandHead, reader)
				if err != nil {
					return
				}
			}
			return
		}()
	}
}

func (t *clientImpl) deferQuicConn(quicConn quic.Connection, err error) {
	if err != nil && !strings.Contains(err.Error(), common.ErrTooManyOpenStreams.Error()) {
		t.forceClose(quicConn, err)
	}
}

func (t *clientImpl) forceClose(quicConn quic.Connection, err error) {
	if t.closed.Load() {
		return
	}
	t.closed.Store(true)
	t.connMutex.Lock()
	if t.onClose != nil {
		go t.onClose()
		t.onClose = nil
	}
	t.connMutex.Unlock()
	// Give 10s for closing.
	time.AfterFunc(10*time.Second, func() {
		t.connMutex.Lock()
		defer t.connMutex.Unlock()
		if quicConn == nil {
			quicConn = t.quicConn
		}
		if quicConn != nil {
			if quicConn == t.quicConn {
				t.quicConn = nil
			}
		}
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		if quicConn != nil {
			_ = quicConn.CloseWithError(ProtocolError, errStr)
		}
		udpInputMap := &t.udpIncomingPacketsMap
		udpInputMap.Range(func(key, value any) bool {
			if conn, ok := value.(net.Conn); ok {
				_ = conn.Close()
			}
			udpInputMap.Delete(key)
			return true
		})
	})
}

func (t *clientImpl) Close() {
	t.forceClose(nil, common.ErrClientClosed)
}

func (t *clientImpl) DialContextWithDialer(ctx context.Context, metadata *protocol.Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (netproxy.Conn, error) {
	if t.closed.Load() {
		return nil, common.ErrClientClosed
	}
	quicConn, err := t.getQuicConn(ctx, dialer, dialFn)
	if err != nil {
		return nil, err
	}
	stream, err := func() (stream net.Conn, err error) {
		defer func() {
			t.deferQuicConn(quicConn, err)
		}()
		connect := NewConnect(NewAddress(metadata))
		buf := pool.Get(connect.BytesLen())
		defer buf.Put()
		n := connect.WriteToBytes(buf)
		if n != len(buf) {
			return nil, fmt.Errorf("n != len(buf)")
		}
		quicStream, err := quicConn.OpenStream()
		if err != nil {
			return nil, err
		}
		stream = common.NewQuicStreamConn(
			quicStream,
			quicConn.LocalAddr(),
			quicConn.RemoteAddr(),
			nil,
		)
		if _, err = stream.Write(buf); err != nil {
			_ = stream.Close()
			return nil, err
		}
		return stream, err
	}()
	if err != nil {
		return nil, err
	}

	return stream, nil
}

func (t *clientImpl) ListenPacketWithDialer(ctx context.Context, metadata *protocol.Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (*quicStreamPacketConn, error) {
	if t.closed.Load() {
		return nil, common.ErrClientClosed
	}
	quicConn, err := t.getQuicConn(ctx, dialer, dialFn)
	if err != nil {
		return nil, err
	}

	var connId uint16
	incomingPackets := newPackets()
	for {
		connId = uint16(fastrand.Intn(0xFFFF))
		_, loaded := t.udpIncomingPacketsMap.LoadOrStore(connId, incomingPackets)
		if !loaded {
			break
		}
	}
	pc := &quicStreamPacketConn{
		connId:                connId,
		quicConn:              quicConn,
		incomingPackets:       incomingPackets,
		udpRelayMode:          t.UdpRelayMode,
		maxUdpRelayPacketSize: t.MaxUdpRelayPacketSize,
		deferQuicConnFn:       t.deferQuicConn,
		closeDeferFn:          nil,
	}
	return pc, nil
}

func (t *clientImpl) setOnClose(f func()) {
	t.onClose = f
}