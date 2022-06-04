package common

import (
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"github.com/eknkc/basex"
	"hash/fnv"
	"math"
	"math/big"
	"math/rand"
	"strings"
)

const Alphabet = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789"
const Alphabet64Grpc = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789_."

var Base62Encoder, _ = basex.NewEncoding(Alphabet)
var Base64GrpcEncoder, _ = basex.NewEncoding(Alphabet64Grpc)

func BytesIncBigEndian(b []byte) {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
}

func BytesIncLittleEndian(b []byte) {
	for i := 0; i < len(b); i++ {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
}

func Abs64(a int64) int64 {
	if a < 0 {
		return -a
	}
	return a
}

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func SeedSecurely() (err error) {
	n, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return err
	}
	rand.Seed(n.Int64())
	return nil
}

// StringToUUID5 is from https://github.com/XTLS/Xray-core/issues/158
func StringToUUID5(str string) string {
	var Nil [16]byte
	h := sha1.New()
	h.Write(Nil[:])
	h.Write([]byte(str))
	u := h.Sum(nil)[:16]
	u[6] = (u[6] & 0x0f) | (5 << 4)
	u[8] = u[8]&(0xff>>2) | (0x02 << 6)
	buf := make([]byte, 36)
	hex.Encode(buf[0:8], u[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], u[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], u[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], u[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:], u[10:])
	return string(buf)
}

func RangeHash(in []byte, minlength int, maxlength int) (out []byte) {
	if minlength > maxlength {
		minlength = maxlength
	}
	h := fnv.New64()
	h.Write(in)
	seed := Abs64(int64(h.Sum64()))
	length := minlength + int(seed%int64(maxlength-minlength+1))
	rnd := rand.New(rand.NewSource(seed))
	out = make([]byte, length)
	rnd.Read(out)
	return out
}

func GenServiceName(b []byte) string {
	if len(b) == 0 {
		return "GunService"
	}
	return Base64GrpcEncoder.Encode(RangeHash(b, 3, 12))
}

func SimplyGetParam(source string, key string) (value string) {
	fields := strings.Split(source, ";")
	for _, field := range fields {
		f := strings.SplitN(field, "=", 2)
		if len(f) == 2 && key == f[0] {
			return f[1]
		}
	}
	return ""
}
