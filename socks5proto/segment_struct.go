package socks5proto

type AuthReq struct {
	VER      byte
	NMETHODS uint8
	METHODS  []byte
}

type AuthResp struct {
	VER    byte
	METHOD byte
}

type AuthUserPasswd struct {
	VER    byte
	ULEN   uint8
	PLEN   uint8
	UNAME  []byte
	PASSWD []byte
}

type AuthCheck struct {
	VER    byte
	STATUS byte
}

type SocksReq struct {
	VER  byte
	CMD  byte
	RSV  byte
	ATYP byte
	PORT uint16
	ADDR []byte
}

type SocksResp struct {
	VER  byte
	REP  byte
	RSV  byte
	ATYP byte
	PORT uint16
	ADDR []byte
}

// type SocksUDP struct {
// 	RSV  [2]byte
// 	FRAG byte
// 	ATYP byte
// 	PORT uint16
// 	ADDR []byte
// 	Data []byte
// }
