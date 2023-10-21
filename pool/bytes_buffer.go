package pool

import (
	"bytes"
	"sync"

	bytes2 "github.com/daeuniverse/softwind/pool/bytes"
)

var bufferPool = sync.Pool{New: func() any { return &bytes.Buffer{} }}

func GetBuffer() *bytes.Buffer {
	return bufferPool.Get().(*bytes.Buffer)
}

func PutBuffer(buf *bytes.Buffer) {
	buf.Reset()
	bufferPool.Put(buf)
}

var bufferPool2 = sync.Pool{New: func() any { return bytes2.NewBuffer(nil) }}

func GetBuffer2() *bytes2.Buffer {
	return bufferPool2.Get().(*bytes2.Buffer)
}

func PutBuffer2(buf *bytes2.Buffer) {
	buf.Reset()
	bufferPool2.Put(buf)
}
