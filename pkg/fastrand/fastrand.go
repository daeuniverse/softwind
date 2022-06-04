package fastrand

import (
	"github.com/mzz2017/softwind/common"
	"math/rand"
)

func init() {
	if err := common.SeedSecurely(); err != nil {
		panic(err)
	}
}

func Intn(n int) int                   { return rand.Intn(n) }
func Float64() float64                 { return rand.Float64() }
func Read(p []byte) (n int, err error) { return rand.Read(p) }
