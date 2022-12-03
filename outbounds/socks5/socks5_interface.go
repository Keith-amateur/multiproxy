package socks5

import "net"

type Socks5 struct {
	Addr       string
	Port       string
	User       string
	Passwd     string
	Methods    []byte
	CurrMethod byte
	Command    byte
}

func (s *Socks5) NetworkAddr() string {
	return net.JoinHostPort(s.Addr, s.Port)
}

func (s *Socks5) Protocol() string {
	return "Socks5"
}

func (s *Socks5) GetSocket(network string) (net.Conn, error) {
	server, err := s.connect()
	if err != nil {
		return nil, err
	}
	err = s.auth(server)
	if err != nil {
		return nil, err
	}

	switch s.CurrMethod {
	case 0x02:
		err = s.send_uname_passwd(server)
		if err != nil {
			return nil, err
		}
	case 0x00:
	}
	err = s.connect_server(server, network)
	if err != nil {
		return nil, err
	}
	return server, nil
}
