package parser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// Well-known ports
const (
	PortHTTP       = 80
	PortHTTPS      = 443
	PortDNS        = 53
	PortDHCPServer = 67
	PortDHCPClient = 68
	PortNTP        = 123
)

// DHCP Magic Cookie
const DHCPMagicCookie = 0x63825363

// DetectApplicationProtocol detects the application layer protocol
func DetectApplicationProtocol(srcPort, dstPort uint16, payload []byte) (string, string) {
	// Port-based detection first
	if srcPort == PortHTTP || dstPort == PortHTTP {
		if isHTTP(payload) {
			return "HTTP", getHTTPInfo(payload)
		}
		return "HTTP", ""
	}

	if srcPort == PortHTTPS || dstPort == PortHTTPS {
		return "HTTPS", "TLS encrypted"
	}

	if srcPort == PortDNS || dstPort == PortDNS {
		if isDNS(payload) {
			return "DNS", getDNSInfo(payload)
		}
		return "DNS", ""
	}

	if (srcPort == PortDHCPServer || srcPort == PortDHCPClient) ||
		(dstPort == PortDHCPServer || dstPort == PortDHCPClient) {
		if isDHCP(payload) {
			return "DHCP", getDHCPInfo(payload)
		}
		return "DHCP", ""
	}

	if srcPort == PortNTP || dstPort == PortNTP {
		if isNTP(payload) {
			return "NTP", getNTPInfo(payload)
		}
		return "NTP", ""
	}

	return "Other", ""
}

// isHTTP checks if payload looks like HTTP
func isHTTP(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	// Check for HTTP methods
	httpMethods := []string{"GET ", "POST", "PUT ", "DELE", "HEAD", "OPTI", "PATC", "TRAC", "CONN"}
	prefix := string(payload[:4])
	for _, method := range httpMethods {
		if strings.HasPrefix(prefix, method) {
			return true
		}
	}
	// Check for HTTP response
	if strings.HasPrefix(string(payload), "HTTP/") {
		return true
	}
	return false
}

// getHTTPInfo extracts HTTP request/response info
func getHTTPInfo(payload []byte) string {
	if len(payload) < 10 {
		return ""
	}

	lines := bytes.SplitN(payload, []byte("\r\n"), 2)
	if len(lines) > 0 {
		firstLine := string(lines[0])
		if len(firstLine) > 100 {
			firstLine = firstLine[:100] + "..."
		}
		return firstLine
	}
	return ""
}

// isDNS checks if payload looks like DNS
func isDNS(payload []byte) bool {
	if len(payload) < 12 {
		return false
	}
	// DNS header is 12 bytes minimum
	// Check if QR bit and opcode look reasonable
	flags := binary.BigEndian.Uint16(payload[2:4])
	opcode := (flags >> 11) & 0x0F
	return opcode <= 5 // Valid opcodes are 0-5
}

// getDNSInfo extracts DNS query info
func getDNSInfo(payload []byte) string {
	if len(payload) < 12 {
		return ""
	}

	flags := binary.BigEndian.Uint16(payload[2:4])
	qr := (flags >> 15) & 0x01
	opcode := (flags >> 11) & 0x0F
	qdcount := binary.BigEndian.Uint16(payload[4:6])
	ancount := binary.BigEndian.Uint16(payload[6:8])

	if qr == 0 {
		return fmt.Sprintf("Query (Questions: %d)", qdcount)
	}
	return fmt.Sprintf("Response (Answers: %d, Opcode: %d)", ancount, opcode)
}

// isDHCP checks if payload looks like DHCP
func isDHCP(payload []byte) bool {
	if len(payload) < 240 {
		return false
	}
	// Check DHCP magic cookie at offset 236
	magicCookie := binary.BigEndian.Uint32(payload[236:240])
	return magicCookie == DHCPMagicCookie
}

// getDHCPInfo extracts DHCP message info
func getDHCPInfo(payload []byte) string {
	if len(payload) < 240 {
		return ""
	}

	op := payload[0]
	htype := payload[1]

	var opStr string
	if op == 1 {
		opStr = "Request"
	} else if op == 2 {
		opStr = "Reply"
	} else {
		opStr = fmt.Sprintf("Op:%d", op)
	}

	return fmt.Sprintf("%s (HW Type: %d)", opStr, htype)
}

// isNTP checks if payload looks like NTP
func isNTP(payload []byte) bool {
	if len(payload) < 48 {
		return false
	}
	// NTP packets are usually 48 bytes
	// Check version (bits 3-5 of first byte) - should be 1-4
	version := (payload[0] >> 3) & 0x07
	return version >= 1 && version <= 4
}

// getNTPInfo extracts NTP message info
func getNTPInfo(payload []byte) string {
	if len(payload) < 48 {
		return ""
	}

	lvm := payload[0]
	mode := lvm & 0x07
	version := (lvm >> 3) & 0x07

	modes := map[uint8]string{
		0: "Reserved",
		1: "Symmetric Active",
		2: "Symmetric Passive",
		3: "Client",
		4: "Server",
		5: "Broadcast",
		6: "NTP Control",
		7: "Reserved for Private",
	}

	modeStr := modes[mode]
	if modeStr == "" {
		modeStr = fmt.Sprintf("Mode %d", mode)
	}

	return fmt.Sprintf("Version %d, %s", version, modeStr)
}
