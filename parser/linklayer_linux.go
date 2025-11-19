//go:build linux

package parser

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
)

// DecodeLinkLayer normalises packets coming from different Linux hatypes into network payloads.
func DecodeLinkLayer(data []byte, ll *unix.SockaddrLinklayer) (uint16, []byte, bool) {
	if ll != nil {
		switch ll.Hatype {
		case unix.ARPHRD_ETHER:
			if len(data) < 14 {
				return 0, nil, false
			}
			return resolveEtherType(binary.BigEndian.Uint16(data[12:14]), data[14:])
		case unix.ARPHRD_LOOPBACK:
			if len(data) < 16 {
				return 0, nil, false
			}
			return resolveEtherType(binary.BigEndian.Uint16(data[14:16]), data[16:])
		case unix.ARPHRD_NONE, unix.ARPHRD_RAWIP, unix.ARPHRD_TUNNEL, unix.ARPHRD_TUNNEL6:
			return inferNetworkPayload(data)
		}
	}

	if len(data) >= 16 {
		etherType := binary.BigEndian.Uint16(data[14:16])
		if etherType == uint16(unix.ETH_P_IP) || etherType == uint16(unix.ETH_P_IPV6) {
			return resolveEtherType(etherType, data[16:])
		}
	}

	return inferNetworkPayload(data)
}

func resolveEtherType(etherType uint16, payload []byte) (uint16, []byte, bool) {
	for {
		switch etherType {
		case uint16(unix.ETH_P_8021Q), uint16(unix.ETH_P_8021AD):
			if len(payload) < 4 {
				return 0, nil, false
			}
			etherType = binary.BigEndian.Uint16(payload[2:4])
			payload = payload[4:]
			continue
		}
		if etherType == uint16(unix.ETH_P_IP) || etherType == uint16(unix.ETH_P_IPV6) {
			return etherType, payload, true
		}
		return 0, nil, false
	}
}

func inferNetworkPayload(data []byte) (uint16, []byte, bool) {
	if len(data) < 1 {
		return 0, nil, false
	}
	switch data[0] >> 4 {
	case 4:
		return uint16(unix.ETH_P_IP), data, true
	case 6:
		return uint16(unix.ETH_P_IPV6), data, true
	default:
		return 0, nil, false
	}
}
