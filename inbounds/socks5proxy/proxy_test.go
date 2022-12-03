package socks5proxy

import (
	"multiproxy/outbounds/socks5"

	// "multiproxy/outbounds"
	"testing"
)

func TestSocks(t *testing.T) {
	s := Socks5Server{
		BindAddr: "127.0.0.1",
		BindPort: "10080",
		UserName: "User",
		PassWord: "Psswd",
		Methods:  []byte{0x02, 0x00},
		// OutProto: &outbounds.Direct{},
		OutProto: &socks5.Socks5{
			Addr:    "127.0.0.1",
			Port:    "10808",
			Methods: []byte{0x00, 0x01},
			Command: 0x01,
		},
	}
	s.Run()
}
