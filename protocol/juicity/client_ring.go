package juicity

import (
	"container/list"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/softwind/netproxy"
	"github.com/daeuniverse/softwind/protocol/trojanc"
	"github.com/daeuniverse/softwind/protocol/tuic/common"
)

type clientRing struct {
	mu        sync.Mutex
	ring      *list.List
	current   *list.Element
	newClient func(capabilityCallback func(n int64)) *clientImpl
	reserved  int64
}

type clientRingNode struct {
	cli *clientImpl
	// capability is protected by quic RWMutex.
	capability int64
}

func newClientRing(newClient func(capabilityCallback func(n int64)) *clientImpl, reserved int64) *clientRing {
	ring := list.New().Init()
	return &clientRing{
		mu:        sync.Mutex{},
		ring:      ring,
		current:   nil,
		newClient: newClient,
		reserved:  reserved,
	}
}

func (r *clientRing) Dial(ctx context.Context, metadata *trojanc.Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (conn *Conn, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	newCurrent := r.current
	err = r._tryNext(&newCurrent, func(node *clientRingNode) error {
		cap := atomic.LoadInt64(&node.capability)
		if cap != -1 && cap <= r.reserved {
			return common.ErrHoldOn
		}
		conn, err = node.cli.Dial(ctx, metadata, dialer, dialFn)
		return err
	})
	r.current = newCurrent
	return conn, err
}

func (r *clientRing) _tryNext(current **list.Element, f func(cli *clientRingNode) error) (err error) {
	var cli *clientRingNode
	if *current == nil {
		goto getNew
	}
	cli = (*current).Value.(*clientRingNode)
	err = f(cli)
	if err == nil {
		// OK.
		return nil
	}

	// Expected error: too many open streams.
	*current = (*current).Next()
	// NOTICE: Add the bellow code to reuse previous clients.
	{
		if *current == nil {
			*current = r.ring.Front()
		}
	}

	if *current == r.current {
		// Clients are exhausted.
		if strings.Contains(err.Error(), common.ErrTooManyOpenStreams.Error()) || errors.Is(err, common.ErrClientClosed) || errors.Is(err, common.ErrHoldOn) {
			goto getNew
		}
		// Not the expected error.
		return err
	}

	return r._tryNext(current, f)

getNew:
	newNode := &clientRingNode{
		cli:        nil,
		capability: -1,
	}
	newCli := r.newClient(func(n int64) { atomic.StoreInt64(&newNode.capability, n) })
	newNode.cli = newCli
	r.current = r._insertAfterCurrent(newNode)
	*current = r.current
	return f(newNode)
}

func (r *clientRing) _insertAfterCurrent(node *clientRingNode) (elem *list.Element) {
	if r.current == nil {
		elem = r.ring.PushBack(node)
		r.current = elem
	} else {
		elem = r.ring.InsertAfter(node, r.current)
	}
	node.cli.setOnClose(func() {
		r.passiveRemove(elem)
	})
	return elem
}

func (r *clientRing) passiveRemove(elem *list.Element) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if elem.Value == nil {
		// Removed.
		return
	}
	elem.Value = nil
	if r.current == elem {
		r.current = elem.Next()
	}
	r.ring.Remove(elem)
}
