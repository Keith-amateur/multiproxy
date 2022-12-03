package socks5

import (
	"errors"
	"multiproxy/socks5proto"
	"net"
	"strconv"
	"strings"
)

func (s *Socks5) connect() (net.Conn, error) {
	server, err := net.Dial("tcp", net.JoinHostPort(s.Addr, s.Port))
	if err != nil {
		return nil, err
	}
	return server, nil
}

func (s *Socks5) auth(server net.Conn) error {
	auth_req := &socks5proto.AuthReq{
		VER:      0x05,
		NMETHODS: uint8(len(s.Methods)),
		METHODS:  s.Methods,
	}
	err := auth_req.Send(server)
	if err != nil {
		return err
	}
	auth_resp := &socks5proto.AuthResp{}
	err = auth_resp.Recv(server)
	if err != nil {
		return err
	}
	s.CurrMethod = auth_resp.METHOD
	return nil
}

func (s *Socks5) send_uname_passwd(server net.Conn) error {
	auth_user_passwd := &socks5proto.AuthUserPasswd{
		VER:    0x05,
		ULEN:   uint8(len(s.User)),
		PLEN:   uint8(len(s.Passwd)),
		UNAME:  []byte(s.User),
		PASSWD: []byte(s.Passwd),
	}
	err := auth_user_passwd.Send(server)
	if err != nil {
		return err
	}
	auth_user_check := &socks5proto.AuthCheck{}
	err = auth_user_check.Recv(server)
	if err != nil {
		return err
	}
	if auth_user_check.STATUS != 0x00 {
		return errors.New("Username or Password Error")
	}
	return nil
}

func (s *Socks5) connect_server(server net.Conn, network string) error {
	socks_req := &socks5proto.SocksReq{
		VER: 0x05,
		CMD: s.Command,
		RSV: 0x00,
	}
	sep_index := strings.LastIndex(network, ":")
	host := network[:sep_index]
	port_str := network[sep_index+1:]
	port, err := strconv.Atoi(port_str)
	if err != nil {
		return errors.New("Parsing Error")
	}
	socks_req.PORT = uint16(port)

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	ip_addr := net.ParseIP(host)
	if ip_addr != nil {
		if ip_addr.To4() != nil {
			socks_req.ATYP = 0x01
			socks_req.ADDR = ip_addr.To4()
		} else {
			socks_req.ATYP = 0x04
			socks_req.ADDR = ip_addr.To16()
		}
	} else {
		socks_req.ATYP = 0x03
		socks_req.ADDR = make([]byte, 1+len(host))
		socks_req.ADDR[0] = uint8(len(host))
		copy(socks_req.ADDR[1:], []byte(host))
	}
	err = socks_req.Send(server)
	if err != nil {
		return err
	}
	socks_resp := &socks5proto.SocksResp{}
	err = socks_resp.Recv(server)
	if err != nil {
		return err
	}
	if socks_resp.REP != 0x00 {
		return errors.New("Refuse by Remote")
	}
	return nil
}
