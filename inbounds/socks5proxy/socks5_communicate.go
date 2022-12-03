package socks5proxy

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"

	"multiproxy/socks5proto"
)

func (server *Socks5Server) auth(sock net.Conn) error {
	auth_req := &socks5proto.AuthReq{}
	err := auth_req.Recv(sock)
	if err != nil {
		return err
	}
	if auth_req.VER != 0x05 {
		return errors.New("Invalid Socks5 Version.")
	}
	for _, server_method := range server.Methods {
		for _, client_method := range auth_req.METHODS {
			if server_method == client_method {
				server.CurrMethod = server_method
				goto break_flag
			}
		}
	}
break_flag:

	auth_resp := &socks5proto.AuthResp{
		VER:    0x05,
		METHOD: server.CurrMethod,
	}
	err = auth_resp.Send(sock)
	if err != nil {
		return err
	}
	return nil
}

func (server *Socks5Server) uname_passwd_check(sock net.Conn) error {
	auth_user_passwd := &socks5proto.AuthUserPasswd{}
	auth_user_check := &socks5proto.AuthCheck{
		VER:    0x01,
		STATUS: 0x00,
	}
	err := auth_user_passwd.Recv(sock)
	if err != nil {
		return err
	}
	if string(auth_user_passwd.UNAME) != server.UserName || string(auth_user_passwd.PASSWD) != server.PassWord {
		auth_user_check.STATUS = 0xff
		auth_user_check.Send(sock)
		return errors.New("Username or Password Error")
	}
	err = auth_user_check.Send(sock)
	if err != nil {
		return err
	}
	return nil
}

func (server *Socks5Server) connect_remote(sock net.Conn) (net.Conn, error) {
	socks_req := &socks5proto.SocksReq{}
	// Fields ADDR and PORT in SocksResp is no use to the client. So I set them to 0 value.
	sock_resp := &socks5proto.SocksResp{
		VER:  0x05,
		REP:  0x00,
		RSV:  0x00,
		ATYP: 0x01,
		ADDR: []byte{0x00, 0x0, 0x00, 0x00},
		PORT: 0,
	}
	err := socks_req.Recv(sock)
	if err != nil {
		return nil, err
	}
	if socks_req.CMD != 0x01 && socks_req.CMD != 0x02 && socks_req.CMD != 0x03 {
		sock_resp.REP = 0x07
		sock_resp.Send(sock)
		return nil, errors.New("Command Not Supported")
	}
	var target_addr string
	switch socks_req.ATYP {
	case 0x01:
		target_addr = fmt.Sprintf("%d.%d.%d.%d", socks_req.ADDR[0], socks_req.ADDR[1], socks_req.ADDR[2], socks_req.ADDR[3])
	case 0x03:
		target_addr = string(socks_req.ADDR)
	case 0x04:
		target_addr = fmt.Sprintf("%X%X:%X%X:%X%X:%X%X:%X%X:%X%X:%X%X:%X%X",
			socks_req.ADDR[0], socks_req.ADDR[1], socks_req.ADDR[2], socks_req.ADDR[3],
			socks_req.ADDR[4], socks_req.ADDR[5], socks_req.ADDR[6], socks_req.ADDR[7],
			socks_req.ADDR[8], socks_req.ADDR[9], socks_req.ADDR[10], socks_req.ADDR[11],
			socks_req.ADDR[12], socks_req.ADDR[13], socks_req.ADDR[14], socks_req.ADDR[15])
	}
	target_port := fmt.Sprintf("%d", socks_req.PORT)
	network := net.JoinHostPort(target_addr, target_port)
	log.Printf("----------Using OutBound %s[%s]----------\n", server.OutProto.Protocol(), server.OutProto.NetworkAddr())
	log.Printf("\t\tconnecting to %s\n", network)
	target_sock, err := server.OutProto.GetSocket(network)
	if err != nil {
		// maybe I will classify the errors someday. Right now just using the unassigned error code
		sock_resp.REP = 0xff
		sock_resp.Send(sock)
		return nil, errors.New("Connect To Remote Target Fail. Error: " + err.Error())
	}
	err = sock_resp.Send(sock)
	if err != nil {
		return nil, err
	}
	return target_sock, nil

}

func (server *Socks5Server) forward_sockets(client_sock, target_sock net.Conn) {
	forwarder := func(dst, src net.Conn) {
		defer src.Close()
		defer dst.Close()
		io.Copy(dst, src)
	}
	go forwarder(client_sock, target_sock)
	go forwarder(target_sock, client_sock)
}
