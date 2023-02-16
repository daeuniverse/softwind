package obfs

import (
	"strings"
)

type creator func() IObfs

var (
	creatorMap = make(map[string]creator)
)

type IObfs interface {
	SetServerInfo(s *ServerInfo)
	GetServerInfo() (s *ServerInfo)
	Encode(data []byte) (encodedData []byte, err error)
	Decode(data []byte) (decodedData []byte, needSendBack bool, err error)
	SetData(data interface{})
	GetData() interface{}
	GetOverhead() int
}

func register(name string, c creator) {
	creatorMap[name] = c
}

// NewObfs create an Obfs object by name and return as an IObfs interface
func NewObfs(name string) IObfs {
	c, ok := creatorMap[strings.ToLower(name)]
	if ok {
		return c()
	}
	return nil
}

type ServerInfo struct {
	Host    string
	Port    uint16
	Param   string

	AddrLen int
	Key     []byte
	IVLen   int
}
