package grpc

import (
	"context"
	"google.golang.org/grpc/stats"
	"sync"
)

type addrTagger struct {
	stats.Handler
	once        sync.Once
	ConnTagInfo *stats.ConnTagInfo
}

func (t *addrTagger) TagConn(ctx context.Context, cti *stats.ConnTagInfo) context.Context {
	t.once.Do(func() {
		t.ConnTagInfo = cti
	})
	return ctx
}
func (t *addrTagger) TagRPC(ctx context.Context, rti *stats.RPCTagInfo) context.Context { return ctx }
func (t *addrTagger) HandleRPC(context.Context, stats.RPCStats)                         {}
func (t *addrTagger) HandleConn(context.Context, stats.ConnStats)                       {}
