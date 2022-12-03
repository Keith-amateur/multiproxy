package socks5proto

import (
	"fmt"
	"testing"
	"unsafe"
)

func TestUnsafe(t *testing.T) {
	test := &AuthReq{
		VER:      0x05,
		NMETHODS: 0x02,
		METHODS:  []byte{0x01, 0x03},
	}
	fmt.Println(unsafe.Sizeof(*test))
	bytes := test.to_bytes()
	fmt.Println(len(bytes))
	fmt.Println(bytes)
}
