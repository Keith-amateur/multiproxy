package socks5proxy

import (
	"fmt"
	"log"
	"multiproxy/outbounds"
	"net"
)

type Socks5Server struct {
	BindAddr   string
	BindPort   string
	UserName   string
	PassWord   string
	Methods    []byte
	CurrMethod byte
	OutProto   outbounds.SocketProto
}

func (s *Socks5Server) Run() {
	sock_listener, err := net.Listen("tcp", s.BindAddr+":"+s.BindPort)
	if err != nil {
		log.Fatalf("Listening on Port %s Fail. Error: %v\n", s.BindPort, err)
	}
	fmt.Printf("Listening on Port %s\n", s.BindPort)

	for {
		client, err := sock_listener.Accept()
		if err != nil {
			log.Printf("Accept Fail. Error: %v\n", err)
			continue
		}
		go s.socks_handler(client)
	}
}

func (server *Socks5Server) socks_handler(client net.Conn) {
	err := server.auth(client)
	if err != nil {
		log.Printf("During Auth, %v\n", err)
		client.Close()
		return
	}
	switch server.CurrMethod {
	case 0x02:
		err = server.uname_passwd_check(client)
		if err != nil {
			log.Printf("During Username/Password check, %v\n", err)
			client.Close()
			return
		}
	case 0x00:
	}
	target_sock, err := server.connect_remote(client)
	if err != nil {
		log.Printf("During Connect, %v\n", err)
		client.Close()
		return
	}
	server.forward_sockets(target_sock, client)
}
