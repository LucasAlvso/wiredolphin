//go:build linux
// +build linux

package capture

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"

	"wiredolphin/logger"
	"wiredolphin/parser"
	"wiredolphin/stats"
)

// Capturer handles raw socket packet capture
type Capturer struct {
	fd        int
	ifaceName string
	stats     *stats.GlobalStats
	logger    *logger.CSVLogger
}

// NewCapturer creates a new packet capturer
func NewCapturer(ifaceName string, globalStats *stats.GlobalStats, csvLogger *logger.CSVLogger) (*Capturer, error) {
	// Create raw socket
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket: %v (are you running as root?)", err)
	}

	// Get interface index
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to get interface %s: %v", ifaceName, err)
	}

	// Bind to interface
	addr := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	if err := unix.Bind(fd, &addr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to bind to interface %s: %v", ifaceName, err)
	}

	return &Capturer{
		fd:        fd,
		ifaceName: ifaceName,
		stats:     globalStats,
		logger:    csvLogger,
	}, nil
}

// Start starts capturing packets
func (c *Capturer) Start(done <-chan struct{}) error {
	buffer := make([]byte, 65535)

	for {
		select {
		case <-done:
			return nil
		default:
			// Set read timeout to allow checking done channel
			tv := unix.Timeval{Sec: 0, Usec: 100000} // 100ms timeout
			if err := unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
				// Non-fatal, continue
			}

			n, from, err := unix.Recvfrom(c.fd, buffer, 0)
			if err != nil {
				// Handle transient/non-fatal errors gracefully
				if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR || err == unix.ENETDOWN {
					// brief pause on ENETDOWN to avoid busy loop
					if err == unix.ENETDOWN {
						time.Sleep(100 * time.Millisecond)
					}
					continue
				}
				return fmt.Errorf("error receiving packet: %v", err)
			}

			if n > 0 {
				// Determine if this link layer has an Ethernet header
				isEthernet := false
				if ll, ok := from.(*unix.SockaddrLinklayer); ok {
					// ARPHRD_ETHER == 1; TUN devices are typically ARPHRD_NONE (65534)
					if ll.Hatype == unix.ARPHRD_ETHER {
						isEthernet = true
					}
				} else {
					// Fallback inference: if payload starts with IPv4/IPv6 version nibble, treat as L3; else assume Ethernet
					if n >= 1 {
						v := buffer[0] >> 4
						if v != 4 && v != 6 {
							isEthernet = true
						}
					} else {
						isEthernet = true
					}
				}
				c.processPacket(buffer[:n], isEthernet)
			}
		}
	}
}

// processPacket processes a captured packet
func (c *Capturer) processPacket(data []byte, isEthernet bool) {
	var etherType uint16
	var payload []byte
	if isEthernet {
		// Expect Ethernet header (14 bytes)
		if len(data) < 14 {
			return
		}
		etherType = uint16(data[12])<<8 | uint16(data[13])
		payload = data[14:]
	} else {
		// No Ethernet header (e.g., TUN devices). Inspect IP version nibble.
		if len(data) < 1 {
			return
		}
		version := data[0] >> 4
		switch version {
		case 4:
			etherType = 0x0800 // IPv4
			payload = data
		case 6:
			etherType = 0x86DD // IPv6
			payload = data
		default:
			return
		}
	}

	pkt := &stats.PacketInfo{
		Timestamp: time.Now(),
		Size:      len(data),
	}

	// Parse based on EtherType
	switch etherType {
	case 0x0800: // IPv4
		c.parseIPv4(payload, pkt)
	case 0x86DD: // IPv6
		c.parseIPv6(payload, pkt)
	default:
		// Unknown network protocol
		return
	}

	// Update stats and log
	if pkt.NetworkProto != "" {
		c.stats.UpdateStats(pkt)
		c.logger.LogPacket(pkt)
	}
}

// parseIPv4 parses an IPv4 packet
func (c *Capturer) parseIPv4(data []byte, pkt *stats.PacketInfo) {
	ipHeader, payload, err := parser.ParseIPv4(data)
	if err != nil {
		return
	}

	pkt.NetworkProto = "IPv4"
	pkt.SrcIP = ipHeader.SrcIP.String()
	pkt.DstIP = ipHeader.DstIP.String()
	pkt.ProtocolNum = ipHeader.Protocol

	// Parse transport layer
	switch ipHeader.Protocol {
	case parser.ProtoTCP:
		c.parseTCP(payload, pkt)
	case parser.ProtoUDP:
		c.parseUDP(payload, pkt)
	case parser.ProtoICMP:
		c.parseICMP(payload, pkt)
	}
}

// parseIPv6 parses an IPv6 packet
func (c *Capturer) parseIPv6(data []byte, pkt *stats.PacketInfo) {
	ipHeader, payload, err := parser.ParseIPv6(data)
	if err != nil {
		return
	}

	pkt.NetworkProto = "IPv6"
	pkt.SrcIP = ipHeader.SrcIP.String()
	pkt.DstIP = ipHeader.DstIP.String()
	pkt.ProtocolNum = ipHeader.NextHeader

	// Parse transport layer
	switch ipHeader.NextHeader {
	case parser.ProtoTCP:
		c.parseTCP(payload, pkt)
	case parser.ProtoUDP:
		c.parseUDP(payload, pkt)
	case parser.ProtoICMPv6:
		pkt.NetworkProto = "ICMPv6"
		pkt.TransportProto = "ICMPv6"
		if icmpHeader, err := parser.ParseICMP(payload); err == nil {
			pkt.ICMPInfo = parser.GetICMPTypeString(icmpHeader.Type)
		}
	}
}

// parseTCP parses a TCP packet
func (c *Capturer) parseTCP(data []byte, pkt *stats.PacketInfo) {
	tcpHeader, payload, err := parser.ParseTCP(data)
	if err != nil {
		return
	}

	pkt.TransportProto = "TCP"
	pkt.SrcPort = tcpHeader.SrcPort
	pkt.DstPort = tcpHeader.DstPort

	// Detect application protocol
	appProto, appInfo := parser.DetectApplicationProtocol(tcpHeader.SrcPort, tcpHeader.DstPort, payload)
	pkt.AppProto = appProto
	pkt.AppInfo = appInfo
}

// parseUDP parses a UDP packet
func (c *Capturer) parseUDP(data []byte, pkt *stats.PacketInfo) {
	udpHeader, payload, err := parser.ParseUDP(data)
	if err != nil {
		return
	}

	pkt.TransportProto = "UDP"
	pkt.SrcPort = udpHeader.SrcPort
	pkt.DstPort = udpHeader.DstPort

	// Detect application protocol
	appProto, appInfo := parser.DetectApplicationProtocol(udpHeader.SrcPort, udpHeader.DstPort, payload)
	pkt.AppProto = appProto
	pkt.AppInfo = appInfo
}

// parseICMP parses an ICMP packet
func (c *Capturer) parseICMP(data []byte, pkt *stats.PacketInfo) {
	icmpHeader, err := parser.ParseICMP(data)
	if err != nil {
		return
	}

	pkt.NetworkProto = "ICMP"
	pkt.TransportProto = "ICMP"
	pkt.ICMPInfo = parser.GetICMPTypeString(icmpHeader.Type)
}

// Close closes the socket
func (c *Capturer) Close() error {
	return unix.Close(c.fd)
}

// htons converts host byte order to network byte order (16-bit)
func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}
