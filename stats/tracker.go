package stats

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// PacketInfo contains parsed packet information
type PacketInfo struct {
	Timestamp      time.Time
	Protocol       string
	SrcIP          string
	DstIP          string
	SrcPort        uint16
	DstPort        uint16
	Size           int
	L3Family       string
	NetworkProto   string
	TransportProto string
	AppProto       string
	ProtocolNum    uint8
	ICMPInfo       string
	AppInfo        string
}

// RemoteHost tracks statistics for a specific remote host
type RemoteHost struct {
	IP              string
	Ports           map[uint16]bool
	Protocols       map[string]bool
	Connections     int
	PacketsSent     int
	PacketsReceived int
	BytesSent       int64
	BytesReceived   int64
	flowKeys        map[flowKey]struct{}
}

type flowKey struct {
	proto      string
	localPort  uint16
	remotePort uint16
}

// ClientStats tracks statistics for a single client
type ClientStats struct {
	IP          string
	RemoteHosts map[string]*RemoteHost
}

// GlobalStats tracks overall statistics
type GlobalStats struct {
	IPv4Count    int
	IPv6Count    int
	ICMPCount    int
	TCPCount     int
	UDPCount     int
	HTTPCount    int
	HTTPSCount   int
	DHCPCount    int
	DNSCount     int
	NTPCount     int
	OtherCount   int
	TotalPackets int
	TotalBytes   int64
	ClientStats  map[string]*ClientStats
	mu           sync.RWMutex
	StartTime    time.Time
	clientNets   []*net.IPNet
}

// NewGlobalStats creates a new GlobalStats instance
func NewGlobalStats() *GlobalStats {
	return &GlobalStats{
		ClientStats: make(map[string]*ClientStats),
		StartTime:   time.Now(),
	}
}

// SetClientFilters sets one or more subnets to consider as "clients" (e.g., tun0 network)
func (gs *GlobalStats) SetClientFilters(cidrs ...*net.IPNet) {
	gs.mu.Lock()
	defer gs.mu.Unlock()

	gs.clientNets = gs.clientNets[:0]
	for _, cidr := range cidrs {
		if cidr == nil || cidr.IP == nil {
			continue
		}
		ip := make(net.IP, len(cidr.IP))
		copy(ip, cidr.IP)
		mask := make(net.IPMask, len(cidr.Mask))
		copy(mask, cidr.Mask)
		gs.clientNets = append(gs.clientNets, &net.IPNet{IP: ip, Mask: mask})
	}
}

// UpdateStats updates global and per-client statistics
func (gs *GlobalStats) UpdateStats(pkt *PacketInfo) {
	gs.mu.Lock()
	defer gs.mu.Unlock()

	gs.TotalPackets++
	gs.TotalBytes += int64(pkt.Size)

	switch pkt.L3Family {
	case "IPv4":
		gs.IPv4Count++
	case "IPv6":
		gs.IPv6Count++
	}

	if pkt.TransportProto == "ICMP" || pkt.TransportProto == "ICMPv6" ||
		pkt.NetworkProto == "ICMP" || pkt.NetworkProto == "ICMPv6" {
		gs.ICMPCount++
	}

	switch pkt.TransportProto {
	case "TCP":
		gs.TCPCount++
	case "UDP":
		gs.UDPCount++
	}

	switch pkt.AppProto {
	case "HTTP":
		gs.HTTPCount++
	case "HTTPS":
		gs.HTTPSCount++
	case "DHCP":
		gs.DHCPCount++
	case "DNS":
		gs.DNSCount++
	case "NTP":
		gs.NTPCount++
	case "Other":
		gs.OtherCount++
	}

	proto := pkt.TransportProto
	if proto == "" {
		proto = pkt.NetworkProto
	}
	if pkt.SrcIP != "" {
		if gs.isClientIP(pkt.SrcIP) {
			gs.updateClientStats(pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort, proto, pkt.Size, true)
		}
	}
	if pkt.DstIP != "" && pkt.SrcIP != pkt.DstIP {
		if gs.isClientIP(pkt.DstIP) {
			gs.updateClientStats(pkt.DstIP, pkt.SrcIP, pkt.DstPort, pkt.SrcPort, proto, pkt.Size, false)
		}
	}
}

func (gs *GlobalStats) updateClientStats(clientIP, remoteIP string, localPort, remotePort uint16, protocol string, size int, isSent bool) {
	client, exists := gs.ClientStats[clientIP]
	if !exists {
		client = &ClientStats{
			IP:          clientIP,
			RemoteHosts: make(map[string]*RemoteHost),
		}
		gs.ClientStats[clientIP] = client
	}

	remote, exists := client.RemoteHosts[remoteIP]
	if !exists {
		remote = &RemoteHost{
			IP:        remoteIP,
			Ports:     make(map[uint16]bool),
			Protocols: make(map[string]bool),
			flowKeys:  make(map[flowKey]struct{}),
		}
		client.RemoteHosts[remoteIP] = remote
	} else if remote.flowKeys == nil {
		remote.flowKeys = make(map[flowKey]struct{})
	}

	if remotePort > 0 {
		remote.Ports[remotePort] = true
	}
	keyProto := protocol
	if keyProto == "" {
		keyProto = "UNKNOWN"
	}
	remote.Protocols[keyProto] = true
	flow := flowKey{
		proto:      keyProto,
		localPort:  localPort,
		remotePort: remotePort,
	}
	if _, seen := remote.flowKeys[flow]; !seen {
		remote.flowKeys[flow] = struct{}{}
		remote.Connections++
	}

	if isSent {
		remote.PacketsSent++
		remote.BytesSent += int64(size)
	} else {
		remote.PacketsReceived++
		remote.BytesReceived += int64(size)
	}
}

// isClientIP checks whether the given IP belongs to a configured client network
func (gs *GlobalStats) isClientIP(ipStr string) bool {
	if len(gs.clientNets) == 0 {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range gs.clientNets {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// GetSnapshot returns a thread-safe copy of current statistics
func (gs *GlobalStats) GetSnapshot() *GlobalStats {
	gs.mu.RLock()
	defer gs.mu.RUnlock()

	snapshot := &GlobalStats{
		IPv4Count:    gs.IPv4Count,
		IPv6Count:    gs.IPv6Count,
		ICMPCount:    gs.ICMPCount,
		TCPCount:     gs.TCPCount,
		UDPCount:     gs.UDPCount,
		HTTPCount:    gs.HTTPCount,
		HTTPSCount:   gs.HTTPSCount,
		DHCPCount:    gs.DHCPCount,
		DNSCount:     gs.DNSCount,
		NTPCount:     gs.NTPCount,
		OtherCount:   gs.OtherCount,
		TotalPackets: gs.TotalPackets,
		TotalBytes:   gs.TotalBytes,
		ClientStats:  make(map[string]*ClientStats),
		StartTime:    gs.StartTime,
	}

	for clientIP, client := range gs.ClientStats {
		clientCopy := &ClientStats{
			IP:          client.IP,
			RemoteHosts: make(map[string]*RemoteHost),
		}
		for remoteIP, remote := range client.RemoteHosts {
			remoteCopy := &RemoteHost{
				IP:              remote.IP,
				Ports:           make(map[uint16]bool),
				Protocols:       make(map[string]bool),
				Connections:     remote.Connections,
				PacketsSent:     remote.PacketsSent,
				PacketsReceived: remote.PacketsReceived,
				BytesSent:       remote.BytesSent,
				BytesReceived:   remote.BytesReceived,
			}
			for port := range remote.Ports {
				remoteCopy.Ports[port] = true
			}
			for proto := range remote.Protocols {
				remoteCopy.Protocols[proto] = true
			}
			clientCopy.RemoteHosts[remoteIP] = remoteCopy
		}
		snapshot.ClientStats[clientIP] = clientCopy
	}

	return snapshot
}

// FormatBytes formats bytes into human-readable format
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
