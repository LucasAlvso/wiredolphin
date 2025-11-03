package parser

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	// IP Protocol Numbers
	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58
)

// IPv4Header represents an IPv4 packet header
type IPv4Header struct {
	Version        uint8
	IHL            uint8
	TOS            uint8
	TotalLength    uint16
	Identification uint16
	Flags          uint8
	FragOffset     uint16
	TTL            uint8
	Protocol       uint8
	Checksum       uint16
	SrcIP          net.IP
	DstIP          net.IP
}

// IPv6Header represents an IPv6 packet header
type IPv6Header struct {
	Version      uint8
	TrafficClass uint8
	FlowLabel    uint32
	PayloadLen   uint16
	NextHeader   uint8
	HopLimit     uint8
	SrcIP        net.IP
	DstIP        net.IP
}

// ICMPHeader represents an ICMP packet header
type ICMPHeader struct {
	Type         uint8
	Code         uint8
	Checksum     uint16
	RestOfHeader uint32
}

// ParseIPv4 parses an IPv4 packet
func ParseIPv4(data []byte) (*IPv4Header, []byte, error) {
	if len(data) < 20 {
		return nil, nil, fmt.Errorf("packet too short for IPv4 header")
	}

	header := &IPv4Header{
		Version:        data[0] >> 4,
		IHL:            data[0] & 0x0F,
		TOS:            data[1],
		TotalLength:    binary.BigEndian.Uint16(data[2:4]),
		Identification: binary.BigEndian.Uint16(data[4:6]),
		Flags:          data[6] >> 5,
		FragOffset:     binary.BigEndian.Uint16(data[6:8]) & 0x1FFF,
		TTL:            data[8],
		Protocol:       data[9],
		Checksum:       binary.BigEndian.Uint16(data[10:12]),
		SrcIP:          net.IP(data[12:16]),
		DstIP:          net.IP(data[16:20]),
	}

	headerLen := int(header.IHL) * 4
	if len(data) < headerLen {
		return nil, nil, fmt.Errorf("packet too short for IPv4 header with options")
	}

	payload := data[headerLen:]
	return header, payload, nil
}

// ParseIPv6 parses an IPv6 packet
func ParseIPv6(data []byte) (*IPv6Header, []byte, error) {
	if len(data) < 40 {
		return nil, nil, fmt.Errorf("packet too short for IPv6 header")
	}

	header := &IPv6Header{
		Version:      data[0] >> 4,
		TrafficClass: ((data[0] & 0x0F) << 4) | (data[1] >> 4),
		FlowLabel:    binary.BigEndian.Uint32([]byte{0, data[1] & 0x0F, data[2], data[3]}),
		PayloadLen:   binary.BigEndian.Uint16(data[4:6]),
		NextHeader:   data[6],
		HopLimit:     data[7],
		SrcIP:        net.IP(data[8:24]),
		DstIP:        net.IP(data[24:40]),
	}

	payload := data[40:]
	return header, payload, nil
}

// ParseICMP parses an ICMP packet
func ParseICMP(data []byte) (*ICMPHeader, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("packet too short for ICMP header")
	}

	header := &ICMPHeader{
		Type:         data[0],
		Code:         data[1],
		Checksum:     binary.BigEndian.Uint16(data[2:4]),
		RestOfHeader: binary.BigEndian.Uint32(data[4:8]),
	}

	return header, nil
}

// GetICMPTypeString returns a human-readable ICMP type
func GetICMPTypeString(icmpType uint8) string {
	types := map[uint8]string{
		0:  "Echo Reply",
		3:  "Destination Unreachable",
		4:  "Source Quench",
		5:  "Redirect",
		8:  "Echo Request",
		11: "Time Exceeded",
		12: "Parameter Problem",
		13: "Timestamp Request",
		14: "Timestamp Reply",
	}
	if str, ok := types[icmpType]; ok {
		return str
	}
	return fmt.Sprintf("Type %d", icmpType)
}

// GetProtocolName returns the protocol name for a protocol number
func GetProtocolName(proto uint8) string {
	switch proto {
	case ProtoICMP:
		return "ICMP"
	case ProtoTCP:
		return "TCP"
	case ProtoUDP:
		return "UDP"
	case ProtoICMPv6:
		return "ICMPv6"
	default:
		return fmt.Sprintf("Proto%d", proto)
	}
}

// StripIPv6Extensions walks IPv6 extension headers and returns the upper-layer protocol and payload.
// The boolean indicates whether the upper-layer payload is present (fragments without the first
// fragment return false but no error). Unsupported extensions such as ESP also return false.
func StripIPv6Extensions(nextHeader uint8, payload []byte) (uint8, []byte, bool, error) {
	upperProto := nextHeader
	remaining := payload

	for {
		switch upperProto {
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
			if len(remaining) < 2 {
				return upperProto, nil, false, fmt.Errorf("ipv6 extension header truncated")
			}
			extLen := int(remaining[1]+1) * 8
			if len(remaining) < extLen {
				return upperProto, nil, false, fmt.Errorf("ipv6 extension length %d exceeds payload %d", extLen, len(remaining))
			}
			upperProto = remaining[0]
			remaining = remaining[extLen:]
		case 44: // Fragment
			if len(remaining) < 8 {
				return upperProto, nil, false, fmt.Errorf("ipv6 fragment header truncated")
			}
			next := remaining[0]
			fragInfo := binary.BigEndian.Uint16(remaining[2:4])
			offset := (fragInfo >> 3) & 0x1FFF
			remaining = remaining[8:]
			if offset != 0 {
				return next, nil, false, nil
			}
			upperProto = next
		case 51: // Authentication Header
			if len(remaining) < 2 {
				return upperProto, nil, false, fmt.Errorf("ipv6 AH truncated")
			}
			extLen := int(remaining[1]+2) * 4
			if len(remaining) < extLen {
				return upperProto, nil, false, fmt.Errorf("ipv6 AH length %d exceeds payload %d", extLen, len(remaining))
			}
			upperProto = remaining[0]
			remaining = remaining[extLen:]
		case 50: // ESP – cannot parse further without SA
			return upperProto, nil, false, nil
		default:
			return upperProto, remaining, true, nil
		}
	}
}
