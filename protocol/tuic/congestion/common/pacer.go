package common

import (
	"math"
	"time"

	"github.com/mzz2017/quic-go/congestion"
)

const (
	maxBurstPackets = 10
)

// Pacer implements a token bucket pacing algorithm.
type Pacer struct {
	budgetAtLastSent congestion.ByteCount
	maxDatagramSize  congestion.ByteCount
	lastSentTime     time.Time
	getBandwidth     func() congestion.ByteCount // in bytes/s
}

func NewPacer(getBandwidth func() congestion.ByteCount) *Pacer {
	p := &Pacer{
		budgetAtLastSent: maxBurstPackets * congestion.InitialPacketSizeIPv4,
		maxDatagramSize:  congestion.InitialPacketSizeIPv4,
		getBandwidth:     getBandwidth,
	}
	return p
}

func (p *Pacer) SentPacket(sendTime time.Time, size congestion.ByteCount) {
	budget := p.Budget(sendTime)
	if size > budget {
		p.budgetAtLastSent = 0
	} else {
		p.budgetAtLastSent = budget - size
	}
	p.lastSentTime = sendTime
}

func (p *Pacer) Budget(now time.Time) congestion.ByteCount {
	if p.lastSentTime.IsZero() {
		return p.maxBurstSize()
	}
	budget := p.budgetAtLastSent + (p.getBandwidth()*congestion.ByteCount(now.Sub(p.lastSentTime).Nanoseconds()))/1e9
	if budget < 0 { // protect against overflows
		budget = congestion.ByteCount(1<<62 - 1)
	}
	return minByteCount(p.maxBurstSize(), budget)
}

func (p *Pacer) maxBurstSize() congestion.ByteCount {
	return maxByteCount(
		congestion.ByteCount((congestion.MinPacingDelay+time.Millisecond).Nanoseconds())*p.getBandwidth()/1e9,
		maxBurstPackets*p.maxDatagramSize,
	)
}

// TimeUntilSend returns when the next packet should be sent.
// It returns the zero value of time.Time if a packet can be sent immediately.
func (p *Pacer) TimeUntilSend() time.Time {
	if p.budgetAtLastSent >= p.maxDatagramSize {
		return time.Time{}
	}
	return p.lastSentTime.Add(maxDuration(
		congestion.MinPacingDelay,
		time.Duration(math.Ceil(float64(p.maxDatagramSize-p.budgetAtLastSent)*1e9/
			float64(p.getBandwidth())))*time.Nanosecond,
	))
}

func (p *Pacer) SetMaxDatagramSize(s congestion.ByteCount) {
	p.maxDatagramSize = s
}

func maxByteCount(a, b congestion.ByteCount) congestion.ByteCount {
	if a < b {
		return b
	}
	return a
}

func minByteCount(a, b congestion.ByteCount) congestion.ByteCount {
	if a < b {
		return a
	}
	return b
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
