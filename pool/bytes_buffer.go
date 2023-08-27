package pool

import (
	"sync"
)

var bufferPool = sync.Pool{New: func() any { return NewBuffer(0) }}

func GetBuffer() *Buffer {
	return bufferPool.Get().(*Buffer)
}

func PutBuffer(buf *Buffer) {
	buf.Reset()
	bufferPool.Put(buf)
}
