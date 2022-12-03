package outbounds

import "net"

type Direct struct{}

func (direct_link *Direct) NetworkAddr() string {
	return ""
}

func (direct_link *Direct) Protocol() string {
	return "Direct"
}

func (direct_link *Direct) GetSocket(network string) (net.Conn, error) {
	socket, err := net.Dial("tcp", network)
	if err != nil {
		return nil, err
	}
	return socket, err
}
