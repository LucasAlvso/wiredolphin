package parser

import (
	"encoding/binary"
	"fmt"
)

// TCPHeader represents a TCP packet header
type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Flags      uint8
	Window     uint16
	Checksum   uint16
	Urgent     uint16
}

// UDPHeader represents a UDP packet header
type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

// TCP Flags
const (
	FlagFIN = 0x01
	FlagSYN = 0x02
	FlagRST = 0x04
	FlagPSH = 0x08
	FlagACK = 0x10
	FlagURG = 0x20
)

// ParseTCP parses a TCP packet
func ParseTCP(data []byte) (*TCPHeader, []byte, error) {
	if len(data) < 20 {
		return nil, nil, fmt.Errorf("packet too short for TCP header")
	}

	header := &TCPHeader{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		SeqNum:     binary.BigEndian.Uint32(data[4:8]),
		AckNum:     binary.BigEndian.Uint32(data[8:12]),
		DataOffset: data[12] >> 4,
		Flags:      data[13],
		Window:     binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		Urgent:     binary.BigEndian.Uint16(data[18:20]),
	}

	headerLen := int(header.DataOffset) * 4
	if len(data) < headerLen {
		return nil, nil, fmt.Errorf("packet too short for TCP header with options")
	}

	payload := data[headerLen:]
	return header, payload, nil
}

// ParseUDP parses a UDP packet
func ParseUDP(data []byte) (*UDPHeader, []byte, error) {
	if len(data) < 8 {
		return nil, nil, fmt.Errorf("packet too short for UDP header")
	}

	header := &UDPHeader{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DstPort:  binary.BigEndian.Uint16(data[2:4]),
		Length:   binary.BigEndian.Uint16(data[4:6]),
		Checksum: binary.BigEndian.Uint16(data[6:8]),
	}

	payload := data[8:]
	return header, payload, nil
}

// GetTCPFlagsString returns a string representation of TCP flags
func GetTCPFlagsString(flags uint8) string {
	var result string
	if flags&FlagFIN != 0 {
		result += "FIN "
	}
	if flags&FlagSYN != 0 {
		result += "SYN "
	}
	if flags&FlagRST != 0 {
		result += "RST "
	}
	if flags&FlagPSH != 0 {
		result += "PSH "
	}
	if flags&FlagACK != 0 {
		result += "ACK "
	}
	if flags&FlagURG != 0 {
		result += "URG "
	}
	if len(result) > 0 {
		return result[:len(result)-1] // Remove trailing space
	}
	return "NONE"
}
