package protocol

type Header struct {
	ProxyAddress    string
	SNI             string
	GrpcServiceName string
	Cipher          string
	Password        string
	IsClient        bool
	Flags           Flags
}

type Flags uint64

const (
	Flags_VMess_UsePacketAddr = 1 << iota
)
