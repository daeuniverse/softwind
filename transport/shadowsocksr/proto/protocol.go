package proto

import (
	"github.com/mzz2017/softwind/transport/shadowsocksr/internal/crypto"
	"strings"
)

type creator func() IProtocol

var (
	creatorMap = make(map[string]creator)
)

type hmacMethod func(key []byte, data []byte) []byte
type hashDigestMethod func(data []byte) []byte
type rndMethod func(dataLength int, random *crypto.Shift128plusContext, lastHash []byte, dataSizeList, dataSizeList2 []int, overhead int) int

type IProtocol interface {
	SetServerInfo(s *ServerInfo)
	GetServerInfo() *ServerInfo
	PreEncrypt(data []byte) ([]byte, error)
	PostDecrypt(data []byte) ([]byte, int, error)
	SetData(data interface{})
	GetData() interface{}
	GetOverhead() int
}

type AuthData struct {
	clientID     []byte
	connectionID uint32
}

func register(name string, c creator) {
	creatorMap[name] = c
}

func NewProtocol(name string) IProtocol {
	c, ok := creatorMap[strings.ToLower(name)]
	if ok {
		return c()
	}
	return nil
}

type ServerInfo struct {
	Param string

	TcpMss   int
	IV       []byte
	Key      []byte
	AddrLen  int
	Overhead int
}
