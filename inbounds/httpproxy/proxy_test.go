package httpproxy

import (
	// "multiproxy/outbounds"
	"multiproxy/outbounds/socks5"
	"testing"
)

func TestHttpProxy(t *testing.T) {
	http_proxy := &HttpProxy{
		BindAddr: "127.0.0.1",
		BindPort: "10090",
		OutProto: &socks5.Socks5{
			Addr:    "127.0.0.1",
			Port:    "10808",
			Methods: []byte{0x00, 0x01},
			Command: 0x01,
		},
		// OutProto: &outbounds.Direct{}
	}
	http_proxy.Run()
}
