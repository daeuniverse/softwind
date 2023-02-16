package obfs

import (
	"errors"
	"github.com/mzz2017/softwind/netproxy"
)

type Dialer struct {
	NextDialer netproxy.Dialer
	param      *ObfsParam

	overhead int
}
type ObfsParam struct {
	ObfsHost  string
	ObfsPort  uint16
	Obfs      string
	ObfsParam string
}

func NewDialer(nextDialer netproxy.Dialer, param *ObfsParam) (*Dialer, error) {

	obfs := NewObfs(param.Obfs)
	if obfs == nil {
		return nil, errors.New("unsupported protocol type: " + param.Obfs)
	}

	d := &Dialer{
		NextDialer: nextDialer,
		param:      param,
		overhead:   obfs.GetOverhead(),
	}
	return d, nil
}

func (d *Dialer) ObfsOverhead() int {
	return d.overhead
}

func (d *Dialer) DialTcp(address string) (netproxy.Conn, error) {
	conn, err := d.NextDialer.DialTcp(address)
	if err != nil {
		return nil, err
	}
	obfs := NewObfs(d.param.Obfs)
	if obfs == nil {
		return nil, errors.New("unsupported protocol type: " + d.param.Obfs)
	}
	obfsServerInfo := &ServerInfo{
		Host:  d.param.ObfsHost,
		Port:  d.param.ObfsPort,
		Param: d.param.ObfsParam,
	}
	obfs.SetData(obfs.GetData())
	obfs.SetServerInfo(obfsServerInfo)

	return NewConn(conn, obfs)
}

func (d *Dialer) DialUdp(address string) (netproxy.PacketConn, error) {
	return nil, netproxy.UnsupportedTunnelTypeError
}
