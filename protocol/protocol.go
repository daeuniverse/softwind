package protocol

import (
	"fmt"
	"github.com/mzz2017/softwind/common"
	"strings"
)

var (
	ErrFailAuth     = fmt.Errorf("fail to authenticate")
	ErrReplayAttack = fmt.Errorf("replay attack")
)

type Protocol string

const (
	ProtocolVMessTCP     Protocol = "vmess"
	ProtocolVMessTlsGrpc Protocol = "vmess+tls+grpc"
	ProtocolShadowsocks  Protocol = "shadowsocks"
)

func (p Protocol) Valid() bool {
	switch p {
	case ProtocolVMessTCP, ProtocolVMessTlsGrpc, ProtocolShadowsocks:
		return true
	default:
		return false
	}
}

func (p Protocol) WithTLS() bool {
	return common.StringsHas(strings.Split(string(p), "+"), "tls")
}
