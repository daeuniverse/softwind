package juicity

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/mzz2017/quic-go"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/pool"
	"github.com/mzz2017/softwind/protocol/trojanc"
	"github.com/mzz2017/softwind/protocol/tuic"
	"github.com/mzz2017/softwind/protocol/tuic/common"
)

type ClientOption struct {
	TlsConfig            *tls.Config
	QuicConfig           *quic.Config
	Uuid                 [16]byte
	Password             string
	CongestionController string
	CWND                 int
}

type clientImpl struct {
	*ClientOption

	quicConn  quic.Connection
	connMutex sync.Mutex

	closed bool

	detachCallback func()
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
	quicConn, err := transport.Dial(ctx, addr, t.TlsConfig, t.QuicConfig)
	if err != nil {
		return nil, err
	}

	common.SetCongestionController(quicConn, t.CongestionController, t.CWND)

	go func() {
		if err := t.sendAuthentication(quicConn); err != nil {
			_ = t.Close()
		}
	}()

	t.quicConn = quicConn
	return quicConn, nil
}

func (t *clientImpl) sendAuthentication(quicConn quic.Connection) (err error) {
	uniStream, err := quicConn.OpenUniStream()
	if err != nil {
		return err
	}
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
	token, err := tuic.GenToken(quicConn.ConnectionState(), t.Uuid, t.Password)
	if err != nil {
		return err
	}
	err = tuic.NewAuthenticate(t.Uuid, token, Version0).WriteTo(buf)
	if err != nil {
		return err
	}
	_, err = buf.WriteTo(uniStream)
	if err != nil {
		return err
	}
	return uniStream.Close()
}

func (t *clientImpl) Close() (err error) {
	t.connMutex.Lock()
	if t.closed {
		t.connMutex.Unlock()
		return
	}
	t.closed = true
	if t.detachCallback != nil {
		go t.detachCallback()
		t.detachCallback = nil
	}
	t.connMutex.Unlock()
	// Give 10s for closing.
	time.AfterFunc(10*time.Second, func() {
		t.connMutex.Lock()
		defer t.connMutex.Unlock()
		if t.quicConn != nil {
			err = t.quicConn.CloseWithError(tuic.ProtocolError, common.ErrClientClosed.Error())
			t.quicConn = nil
		}
	})
	return err
}

func (t *clientImpl) Dial(ctx context.Context, metadata *trojanc.Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (*Conn, error) {
	if t.closed {
		return nil, common.ErrClientClosed
	}
	quicConn, err := t.getQuicConn(ctx, dialer, dialFn)
	if err != nil {
		return nil, fmt.Errorf("getQuicConn: %w", err)
	}
	quicStream, err := quicConn.OpenStream()
	if err != nil {
		t.connMutex.Lock()
		// Detach it from pool due to bad connection.
		if t.detachCallback != nil {
			go t.detachCallback()
			t.detachCallback = nil
		}
		t.connMutex.Unlock()
		return nil, fmt.Errorf("OpenStream: %w", err)
	}
	stream := NewConn(
		quicStream,
		metadata,
		nil,
	)
	return stream, nil
}

func (t *clientImpl) setOnClose(f func()) {
	t.detachCallback = f
}
