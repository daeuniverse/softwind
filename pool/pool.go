// modified from https://github.com/nadoo/glider/blob/master/pool/buffer.go

package pool

import (
	"math/bits"
	"sync"
)

const (
	// number of pools.
	num          = 17
	maxsize      = 1 << (num - 1)
	minsizePower = 6
	minsize      = 1 << minsizePower
)

var (
	pools [num]sync.Pool
)

func init() {
	for i := minsizePower; i < num; i++ {
		size := 1 << i
		pools[i].New = func() interface{} {
			return make([]byte, size)
		}
	}
}

func GetClosestN(need int) (n int) {
	// if need is exactly 2^n, return n-1
	if need&(need-1) == 0 {
		return bits.Len32(uint32(need)) - 1
	}
	// or return its closest n
	return bits.Len32(uint32(need))
}

func GetBiggerClosestN(need int) (n int) {
	// or return its closest n
	return bits.Len32(uint32(need))
}

// Get gets a buffer from pool, size should in range: [1, 65536],
// otherwise, this function will call make([]byte, size) directly.
func Get(size int) PB {
	if size >= 1 && size <= maxsize {
		i := GetClosestN(size)
		if i < minsizePower {
			i = minsizePower
		}
		return pools[i].Get().([]byte)[:size]
	}
	return make([]byte, size)
}

func GetFullCap(size int) PB {
	a := Get(size)
	a = a[:cap(a)]
	return a
}

func GetMustBigger(size int) PB {
	if size >= 1 && size <= maxsize {
		i := GetBiggerClosestN(size)
		if i < minsizePower {
			i = minsizePower
		}
		return pools[i].Get().([]byte)[:size]
	}
	return make([]byte, size)
}

// GetZero returns buffer and set all the values to 0
func GetZero(size int) []byte {
	b := Get(size)
	for i := range b {
		b[i] = 0
	}
	return b
}

// Put puts a buffer into pool.
func Put(buf []byte) {
	if size := cap(buf); size >= 1 && size <= maxsize {
		i := GetClosestN(size)
		if i < num {
			pools[i].Put(buf)
		}
	}
}
