package socks5proto

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

type Proto interface {
	Recv(net.Conn) []byte
	Send(net.Conn) []byte
}

func (auth_req *AuthReq) to_bytes() []byte {
	byte_stream := make([]byte, 2+auth_req.NMETHODS)
	byte_stream[0] = auth_req.VER
	byte_stream[1] = auth_req.NMETHODS
	copy(byte_stream[2:], auth_req.METHODS)
	return byte_stream
}

func (auth_req *AuthReq) Recv(sock net.Conn) error {
	read_bytes := make([]byte, 2)
	_, err := io.ReadFull(sock, read_bytes)
	if err != nil {
		return errors.New("AuthReq Recv Fail, reading VER and NMETHODS. Error: " + err.Error())
	}
	auth_req.VER, auth_req.NMETHODS = read_bytes[0], read_bytes[1]
	auth_req.METHODS = make([]byte, auth_req.NMETHODS)
	_, err = io.ReadFull(sock, auth_req.METHODS)
	if err != nil {
		return errors.New("AuthReq Recv Fail, reading METHODS. Error: " + err.Error())
	}
	return nil
}

func (auth_req *AuthReq) Send(sock net.Conn) error {
	err := binary.Write(sock, binary.BigEndian, auth_req.to_bytes())
	if err != nil {
		return errors.New("AuthReq Send Fail. Error: " + err.Error())
	}
	return nil
}

func (auth_resp *AuthResp) Recv(sock net.Conn) error {
	err := binary.Read(sock, binary.BigEndian, auth_resp)
	if err != nil {
		return errors.New("AuthResp Recv Fail. Error: " + err.Error())
	}
	return nil
}

func (auth_resp *AuthResp) Send(sock net.Conn) error {
	err := binary.Write(sock, binary.BigEndian, auth_resp)
	if err != nil {
		return errors.New("AuthResp Send Fail. Error: " + err.Error())
	}
	return nil
}

func (socks_req *SocksReq) to_bytes() []byte {
	byte_stream := make([]byte, 4+len(socks_req.ADDR)+2)
	byte_stream[0] = socks_req.VER
	byte_stream[1] = socks_req.CMD
	byte_stream[2] = socks_req.RSV
	byte_stream[3] = socks_req.ATYP
	addr_len := copy(byte_stream[4:], socks_req.ADDR)
	binary.BigEndian.PutUint16(byte_stream[4+addr_len:], socks_req.PORT)
	return byte_stream
}

func (socks_req *SocksReq) Recv(sock net.Conn) error {
	read_bytes := make([]byte, 4)
	_, err := io.ReadFull(sock, read_bytes)
	if err != nil {
		return errors.New("SocksReq Recv Fail. Error: " + err.Error())
	}
	socks_req.VER = read_bytes[0]
	socks_req.CMD = read_bytes[1]
	socks_req.RSV = read_bytes[2]
	socks_req.ATYP = read_bytes[3]
	switch socks_req.ATYP {
	case 0x01:
		socks_req.ADDR = make([]byte, 4)
		_, err = io.ReadFull(sock, socks_req.ADDR)
	case 0x03:
		domain_len := make([]byte, 1)
		_, err = io.ReadFull(sock, domain_len)
		socks_req.ADDR = make([]byte, domain_len[0])
		_, err = io.ReadFull(sock, socks_req.ADDR)
	case 0x04:
		socks_req.ADDR = make([]byte, 16)
		_, err = io.ReadFull(sock, socks_req.ADDR)
	default:
		return errors.New("SocksReq.ATYP Invalid.")
	}
	if err != nil {
		return errors.New("SocksReq.ADDR Recv Fail. Error: " + err.Error())
	}
	err = binary.Read(sock, binary.BigEndian, &socks_req.PORT)
	if err != nil {
		return errors.New("SocksReq.PORT Recv Fail. Error: " + err.Error())
	}
	return nil
}

func (socks_req *SocksReq) Send(sock net.Conn) error {
	err := binary.Write(sock, binary.BigEndian, socks_req.to_bytes())
	if err != nil {
		return errors.New("SocksReq Send Fail. Error: " + err.Error())
	}
	return nil
}

func (sock_resp *SocksResp) to_bytes() []byte {
	byte_stream := make([]byte, 4+len(sock_resp.ADDR)+2)
	byte_stream[0] = sock_resp.VER
	byte_stream[1] = sock_resp.REP
	byte_stream[2] = sock_resp.RSV
	byte_stream[3] = sock_resp.ATYP
	addr_len := copy(byte_stream[4:], sock_resp.ADDR)
	binary.BigEndian.PutUint16(byte_stream[4+addr_len:], sock_resp.PORT)
	return byte_stream
}

func (sock_resp *SocksResp) Recv(sock net.Conn) error {
	read_bytes := make([]byte, 4)
	_, err := io.ReadFull(sock, read_bytes)
	if err != nil {
		return errors.New("SocksResp Recv Fail. Error: " + err.Error())
	}
	sock_resp.VER = read_bytes[0]
	sock_resp.REP = read_bytes[1]
	sock_resp.REP = read_bytes[2]
	sock_resp.ATYP = read_bytes[3]
	switch sock_resp.ATYP {
	case 0x01:
		sock_resp.ADDR = make([]byte, 4)
		_, err = io.ReadFull(sock, sock_resp.ADDR)
	case 0x03:
		var domain_len uint8
		err = binary.Read(sock, binary.BigEndian, &domain_len)
		sock_resp.ADDR = make([]byte, domain_len)
		_, err = io.ReadFull(sock, sock_resp.ADDR)
	case 0x04:
		sock_resp.ADDR = make([]byte, 16)
		_, err = io.ReadFull(sock, sock_resp.ADDR)
	default:
		return errors.New("SocksResp.ATYP Invalid.")
	}
	if err != nil {
		return errors.New("SocksResp.ADDR Recv Fail. Error: " + err.Error())
	}
	err = binary.Read(sock, binary.BigEndian, &sock_resp.PORT)
	if err != nil {
		return errors.New("SocksResp.PORT Recv Fail. Error: " + err.Error())
	}
	return nil
}

func (sock_resp *SocksResp) Send(sock net.Conn) error {
	err := binary.Write(sock, binary.BigEndian, sock_resp.to_bytes())
	if err != nil {
		return errors.New("SocksResp Send Fail. Error: " + err.Error())
	}
	return nil
}

func (auth_user_passwd *AuthUserPasswd) to_bytes() []byte {
	byte_stream := make([]byte, 2+auth_user_passwd.ULEN+1+auth_user_passwd.PLEN)
	byte_stream[0] = auth_user_passwd.VER
	byte_stream[1] = auth_user_passwd.ULEN
	copy(byte_stream[2:], auth_user_passwd.UNAME)
	byte_stream[2+auth_user_passwd.ULEN] = auth_user_passwd.PLEN
	copy(byte_stream[2+auth_user_passwd.ULEN+1:], auth_user_passwd.PASSWD)
	return byte_stream
}

func (auth_user_passwd *AuthUserPasswd) Recv(sock net.Conn) error {
	read_bytes := make([]byte, 2)
	_, err := io.ReadFull(sock, read_bytes)
	if err != nil {
		return errors.New("AuthUserPasswd Recv Fail. Error: " + err.Error())
	}
	auth_user_passwd.VER = read_bytes[0]
	auth_user_passwd.ULEN = read_bytes[1]
	auth_user_passwd.UNAME = make([]byte, auth_user_passwd.ULEN)
	_, err = io.ReadFull(sock, auth_user_passwd.UNAME)
	if err != nil {
		return errors.New("AuthUserPasswd.UNAME Recv Fail. Error: " + err.Error())
	}
	err = binary.Read(sock, binary.BigEndian, &auth_user_passwd.PLEN)
	if err != nil {
		return errors.New("AuthUserPasswd.PLEN Recv Fail. Error: " + err.Error())
	}
	auth_user_passwd.PASSWD = make([]byte, auth_user_passwd.PLEN)
	_, err = io.ReadFull(sock, auth_user_passwd.PASSWD)
	if err != nil {
		return errors.New("AuthUserPasswd.PASSWD Recv Fail. Error: " + err.Error())
	}
	return nil
}

func (auth_user_passwd *AuthUserPasswd) Send(sock net.Conn) error {
	err := binary.Write(sock, binary.BigEndian, auth_user_passwd.to_bytes())
	if err != nil {
		sock.Close()
		return errors.New("AuthUserPasswd Send Fail. Error: " + err.Error())
	}
	return nil
}

func (auth_check *AuthCheck) Recv(sock net.Conn) error {
	err := binary.Read(sock, binary.BigEndian, auth_check)
	if err != nil {
		return errors.New("AuthCheck Recv Fail. Error: " + err.Error())
	}
	return nil
}

func (auth_check *AuthCheck) Send(sock net.Conn) error {
	err := binary.Write(sock, binary.BigEndian, auth_check)
	if err != nil {
		return errors.New("AuthCheck Send Fail. Error: " + err.Error())
	}
	return nil
}
