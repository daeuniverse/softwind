package common

import (
	"net"
	"sync"
	"time"

	"github.com/mzz2017/quic-go"
)

type quicStreamConn struct {
	quic.Stream
	lock  sync.Mutex
	lAddr net.Addr
	rAddr net.Addr

	closeDeferFn func()

	closeOnce sync.Once
	closeErr  error

	muTimer            sync.Mutex
	readDeadlineTimer  *time.Timer
	writeDeadlineTimer *time.Timer
}

func (q *quicStreamConn) Write(p []byte) (n int, err error) {
	q.lock.Lock()
	defer q.lock.Unlock()
	return q.Stream.Write(p)
}

func (q *quicStreamConn) Close() error {
	q.closeOnce.Do(func() {
		q.closeErr = q.close()
	})
	return q.closeErr
}

func (q *quicStreamConn) SetDeadline(t time.Time) error {
	_ = q.SetReadDeadline(t)
	_ = q.SetWriteDeadline(t)
	return nil
}

func (q *quicStreamConn) SetReadDeadline(t time.Time) error {
	q.muTimer.Lock()
	defer q.muTimer.Unlock()
	dur := time.Until(t)
	if q.readDeadlineTimer != nil {
		q.readDeadlineTimer.Reset(dur)
	} else {
		q.readDeadlineTimer = time.AfterFunc(dur, func() {
			_ = q.Stream.SetReadDeadline(time.Now())
			q.muTimer.Lock()
			defer q.muTimer.Unlock()
			q.lock.Lock()
			defer q.lock.Unlock()
			q.Stream.CancelRead(0)
			q.readDeadlineTimer = nil
		})
	}
	return nil
}

func (q *quicStreamConn) SetWriteDeadline(t time.Time) error {
	q.muTimer.Lock()
	defer q.muTimer.Unlock()
	dur := time.Until(t)
	if q.writeDeadlineTimer != nil {
		q.writeDeadlineTimer.Reset(dur)
	} else {
		q.writeDeadlineTimer = time.AfterFunc(dur, func() {
			_ = q.Stream.SetWriteDeadline(time.Now())
			q.muTimer.Lock()
			defer q.muTimer.Unlock()
			q.lock.Lock()
			defer q.lock.Unlock()
			q.Stream.CancelWrite(0)
			q.writeDeadlineTimer = nil
		})
	}
	return nil
}

func (q *quicStreamConn) CloseWrite() error {
	_ = q.Stream.SetWriteDeadline(time.Now())
	q.lock.Lock()
	defer q.lock.Unlock()
	q.Stream.CancelWrite(0)
	return nil
}

func (q *quicStreamConn) close() error {
	if q.closeDeferFn != nil {
		defer q.closeDeferFn()
	}

	// https://github.com/cloudflare/cloudflared/commit/ed2bac026db46b239699ac5ce4fcf122d7cab2cd
	// Make sure a possible writer does not block the lock forever. We need it, so we can close the writer
	// side of the stream safely.
	_ = q.Stream.SetWriteDeadline(time.Now())

	// This lock is eventually acquired despite Write also acquiring it, because we set a deadline to writes.
	q.lock.Lock()
	defer q.lock.Unlock()

	// We have to clean up the receiving stream ourselves since the Close in the bottom does not handle that.
	q.Stream.CancelRead(0)
	return q.Stream.Close()
}

func (q *quicStreamConn) LocalAddr() net.Addr {
	return q.lAddr
}

func (q *quicStreamConn) RemoteAddr() net.Addr {
	return q.rAddr
}

var _ net.Conn = (*quicStreamConn)(nil)

func NewQuicStreamConn(stream quic.Stream, lAddr, rAddr net.Addr, closeDeferFn func()) net.Conn {
	return &quicStreamConn{Stream: stream, lAddr: lAddr, rAddr: rAddr, closeDeferFn: closeDeferFn}
}
