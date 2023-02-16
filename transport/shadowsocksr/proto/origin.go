package proto

func init() {
	register("origin", NewOrigin)
}

type origin struct {
	ServerInfo
}

func NewOrigin() IProtocol {
	a := &origin{}
	return a
}

func (o *origin) SetServerInfo(s *ServerInfo) {
	o.ServerInfo = *s
}

func (o *origin) GetServerInfo() (s *ServerInfo) {
	return &o.ServerInfo
}

func (o *origin) PreEncrypt(data []byte) (encryptedData []byte, err error) {
	return data, nil
}

func (o *origin) PostDecrypt(data []byte) ([]byte, int, error) {
	return data, len(data), nil
}

func (o *origin) SetData(data interface{}) {

}

func (o *origin) GetData() interface{} {
	return nil
}

func (o *origin) GetOverhead() int {
	return 0
}
