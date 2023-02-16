package obfs

import (
	"errors"
	"github.com/mzz2017/softwind/netproxy"
)

type Dialer struct {
	NextDialer netproxy.Dialer
	param      *ObfsParam

	obfs IObfs
}
type ObfsParam struct {
	ObfsHost  string
	ObfsPort  uint16
	Obfs      string
	ObfsParam string
}

func NewDialer(nextDialer netproxy.Dialer, param *ObfsParam) (*Dialer, error) {
	d := &Dialer{
		NextDialer: nextDialer,
		param:      param,
		obfs:       NewObfs(param.Obfs),
	}
	if d.obfs == nil {
		return nil, errors.New("unsupported protocol type: " + d.param.Obfs)
	}
	obfsServerInfo := &ServerInfo{
		Host:  d.param.ObfsHost,
		Port:  d.param.ObfsPort,
		Param: d.param.ObfsParam,
	}
	d.obfs.SetData(d.obfs.GetData())
	d.obfs.SetServerInfo(obfsServerInfo)
	return d, nil
}

func (d *Dialer) ObfsOverhead() int {
	return d.obfs.GetOverhead()
}

func (d *Dialer) DialTcp(address string) (netproxy.Conn, error) {
	conn, err := d.NextDialer.DialTcp(address)
	if err != nil {
		return nil, err
	}
	return NewConn(conn, d.obfs)
}

func (d *Dialer) DialUdp(address string) (netproxy.PacketConn, error) {
	return nil, netproxy.UnsupportedTunnelTypeError
}
