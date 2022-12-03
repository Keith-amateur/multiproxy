package outbounds

import "net"

type SocketProto interface {
	GetSocket(network string) (net.Conn, error)
	NetworkAddr() string
	Protocol() string
}
