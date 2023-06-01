package requests

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/xmapst/requests/tools"
)

type pwdConn struct {
	rawConn            net.Conn
	proxyAuthorization string
}

func (obj *pwdConn) Write(b []byte) (n int, err error) {
	if obj.proxyAuthorization == "" {
		return obj.rawConn.Write(b)
	}
	b = bytes.Replace(b, []byte("\r\n"), tools.StringToBytes(fmt.Sprintf("\r\nProxy-Authorization: Basic %s\r\n", obj.proxyAuthorization)), 1)
	obj.proxyAuthorization = ""
	return obj.rawConn.Write(b)
}
func (obj *pwdConn) Read(b []byte) (n int, err error) {
	return obj.rawConn.Read(b)
}
func (obj *pwdConn) Close() error {
	if obj.rawConn != nil {
		return obj.rawConn.Close()
	}
	return nil
}
func (obj *pwdConn) LocalAddr() net.Addr {
	return obj.rawConn.LocalAddr()
}
func (obj *pwdConn) RemoteAddr() net.Addr {
	return obj.rawConn.RemoteAddr()
}
func (obj *pwdConn) SetDeadline(t time.Time) error {
	return obj.rawConn.SetDeadline(t)
}
func (obj *pwdConn) SetReadDeadline(t time.Time) error {
	return obj.rawConn.SetReadDeadline(t)
}
func (obj *pwdConn) SetWriteDeadline(t time.Time) error {
	return obj.rawConn.SetWriteDeadline(t)
}
