package httpproxy

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"multiproxy/outbounds"
	"net"
	"net/url"
	"strings"
)

type HttpProxy struct {
	BindAddr string
	BindPort string
	OutProto outbounds.SocketProto
}

func (http *HttpProxy) Run() {
	listener, err := net.Listen("tcp", net.JoinHostPort(http.BindAddr, http.BindPort))
	if err != nil {
		log.Fatalf("Listen on Port %s Fail. Error: %v\n", http.BindPort, err)
	}
	fmt.Println("HTTP Proxy Listening on Port " + http.BindPort)
	for {
		client, err := listener.Accept()
		if err != nil {
			log.Printf("Accept Fail. Error: %v\n", err)
			continue
		}
		go http.forward_traffic(client)
	}
}

func (http *HttpProxy) forward_traffic(client net.Conn) {
	buf_reader := bufio.NewReader(client)
	first_line, err := buf_reader.ReadString('\n')
	if err != nil {
		client.Close()
		return
	}
	header := strings.Split(first_line, " ")
	var method, request_url, proto string
	method, request_url, proto = header[0], header[1], header[2]
	parse_url, err := url.Parse(request_url)
	if err != nil {
		log.Printf("Parsing %s Fail. Error: %v\n", request_url, err)
		client.Close()
		return
	}
	var network_address string
	switch method {
	case "GET":
		if strings.Index(parse_url.Host, ":") == -1 {
			network_address = parse_url.Host + ":80"
		}
	case "CONNECT":
		network_address = parse_url.Scheme + ":" + parse_url.Opaque
	default:
		log.Printf("invlalid method, %s\n", method)
		client.Close()
		return
	}
	target_socket, err := http.OutProto.GetSocket(network_address)
	if err != nil {
		log.Printf("[OutBound - %s]Connecting to %s Fail. Error: %v\n", http.OutProto.Protocol(), http.OutProto.Protocol(), err)
		return
	}
	log.Printf("----------Using OutBound %s [%s]----------\n", http.OutProto.Protocol(), http.OutProto.NetworkAddr())
	log.Printf("\t\tconnecting to %s\n", network_address)
	switch method {
	case "GET":
		http_content := make([]byte, 1024)
		new_first_line := method + " " + parse_url.Path + " " + proto
		first_line_len := copy(http_content[:], []byte(new_first_line))
		rest_len, err := buf_reader.Read(http_content[first_line_len:])
		if err != nil {
			client.Close()
			target_socket.Close()
			log.Printf("Reading HTTP Content Fail. Error: %v\n", err)
			return
		}
		target_socket.Write(http_content[:first_line_len+rest_len])
	case "CONNECT":
		_, err = fmt.Fprint(client, "HTTP/1.1 200 Connection established\r\n\r\n")
		if err != nil {
			client.Close()
			target_socket.Close()
			log.Printf("Proxy HTTPS Traffic Fail. Error: %v\n", err)
			return
		}
	}
	forwarder := func(src, dst net.Conn) {
		defer src.Close()
		defer dst.Close()
		io.Copy(dst, src)
	}
	go forwarder(target_socket, client)
	go forwarder(client, target_socket)
}
