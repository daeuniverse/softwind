package common

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/eknkc/basex"
	"net"
	"net/netip"
	"strconv"
	"time"
)

const Alphabet = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789"
const Alphabet64Grpc = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789_."

var Base62Encoder, _ = basex.NewEncoding(Alphabet)
var Base64GrpcEncoder, _ = basex.NewEncoding(Alphabet64Grpc)
var IntSize = 32 << (^uint(0) >> 63)

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

func StringsHas(strs []string, str string) bool {
	for _, s := range strs {
		if s == str {
			return true
		}
	}
	return false
}

func HeadOverlap(p, b []byte) bool {
	return len(p) > 0 && len(b) > 0 && &p[0] == &b[0]
}

func ResolveUDPAddr(resolver *net.Resolver, hostport string) (*net.UDPAddr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	host, _port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(_port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", _port)
	}
	addrs, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	// Prefer ipv4.
	var ip netip.Addr
	for _, addr := range addrs {
		if !ip.IsValid() {
			ip = addr
			continue
		}
		if addr.Is4() {
			ip = addr
			break
		}
	}
	if !ip.IsValid() {
		return nil, errors.New("no suitable address found")
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(port))), nil
}
