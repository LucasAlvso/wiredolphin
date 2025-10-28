package ui

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"wiredolphin/stats"
)

// TUI handles terminal user interface
type TUI struct {
	stats *stats.GlobalStats
	iface string
}

// NewTUI creates a new TUI
func NewTUI(globalStats *stats.GlobalStats, iface string) *TUI {
	return &TUI{
		stats: globalStats,
		iface: iface,
	}
}

// Start starts the TUI update loop
func (t *TUI) Start(done <-chan struct{}) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			t.Render()
		}
	}
}

// Render renders the TUI
func (t *TUI) Render() {
	clearScreen()

	snapshot := t.stats.GetSnapshot()

	// Header
	fmt.Println("=" + strings.Repeat("=", 78) + "=")
	fmt.Println(centerText("NETWORK TRAFFIC MONITOR - Real-Time Statistics", 80))
	fmt.Println("=" + strings.Repeat("=", 78) + "=")
	uptime := time.Since(snapshot.StartTime)
	fmt.Printf("Uptime: %s | Interface: %s\n", formatDuration(uptime), t.iface)
	fmt.Println()

	// Global Statistics
	fmt.Println("GLOBAL STATISTICS")
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("Total Packets: %-10d | Total Bytes: %s\n",
		snapshot.TotalPackets, stats.FormatBytes(snapshot.TotalBytes))
	fmt.Println()

	// Network Layer
	fmt.Println("Network Layer:")
	fmt.Printf("  IPv4: %-8d  IPv6: %-8d  ICMP: %-8d\n",
		snapshot.IPv4Count, snapshot.IPv6Count, snapshot.ICMPCount)
	fmt.Println()

	// Transport Layer
	fmt.Println("Transport Layer:")
	fmt.Printf("  TCP:  %-8d  UDP:  %-8d\n",
		snapshot.TCPCount, snapshot.UDPCount)
	fmt.Println()

	// Application Layer
	fmt.Println("Application Layer:")
	fmt.Printf("  HTTP: %-8d  HTTPS: %-8d  DNS:  %-8d\n",
		snapshot.HTTPCount, snapshot.HTTPSCount, snapshot.DNSCount)
	fmt.Printf("  DHCP: %-8d  NTP:   %-8d  Other: %-8d\n",
		snapshot.DHCPCount, snapshot.NTPCount, snapshot.OtherCount)
	fmt.Println()

	// Per-Client Statistics
	if len(snapshot.ClientStats) > 0 {
		fmt.Println(strings.Repeat("=", 80))
		fmt.Println("PER-CLIENT STATISTICS")
		fmt.Println(strings.Repeat("=", 80))

		// Sort clients by IP
		var clientIPs []string
		for ip := range snapshot.ClientStats {
			clientIPs = append(clientIPs, ip)
		}
		sort.Strings(clientIPs)

		// Display up to 5 clients
		displayCount := len(clientIPs)
		if displayCount > 5 {
			displayCount = 5
		}

		for i := 0; i < displayCount; i++ {
			clientIP := clientIPs[i]
			client := snapshot.ClientStats[clientIP]

			fmt.Printf("\nClient: %s\n", client.IP)
			fmt.Println(strings.Repeat("-", 80))

			// Get remote hosts, sorted by traffic volume
			type remoteStats struct {
				ip           string
				host         *stats.RemoteHost
				totalTraffic int64
			}
			var remotes []remoteStats
			for remoteIP, remote := range client.RemoteHosts {
				remotes = append(remotes, remoteStats{
					ip:           remoteIP,
					host:         remote,
					totalTraffic: remote.BytesSent + remote.BytesReceived,
				})
			}
			sort.Slice(remotes, func(i, j int) bool {
				return remotes[i].totalTraffic > remotes[j].totalTraffic
			})

			// Display top 3 remote hosts for this client
			remoteDisplayCount := len(remotes)
			if remoteDisplayCount > 3 {
				remoteDisplayCount = 3
			}

			for j := 0; j < remoteDisplayCount; j++ {
				remote := remotes[j]

				// Get ports list
				var ports []uint16
				for port := range remote.host.Ports {
					ports = append(ports, port)
				}
				sort.Slice(ports, func(a, b int) bool { return ports[a] < ports[b] })
				portsStr := formatPorts(ports)

				// Get protocols list
				var protocols []string
				for proto := range remote.host.Protocols {
					protocols = append(protocols, proto)
				}
				sort.Strings(protocols)
				protocolsStr := strings.Join(protocols, ", ")

				fmt.Printf("  Remote: %-45s\n", remote.ip)
				fmt.Printf("    Ports:      %s\n", portsStr)
				fmt.Printf("    Protocols:  %s\n", protocolsStr)
				fmt.Printf("    Packets:    Sent: %-6d  Received: %-6d  Total: %-6d\n",
					remote.host.PacketsSent, remote.host.PacketsReceived,
					remote.host.PacketsSent+remote.host.PacketsReceived)
				fmt.Printf("    Traffic:    Sent: %-10s  Received: %-10s  Total: %s\n",
					stats.FormatBytes(remote.host.BytesSent),
					stats.FormatBytes(remote.host.BytesReceived),
					stats.FormatBytes(remote.host.BytesSent+remote.host.BytesReceived))
				fmt.Println()
			}

			if len(remotes) > remoteDisplayCount {
				fmt.Printf("  ... and %d more remote host(s)\n", len(remotes)-remoteDisplayCount)
			}
		}

		if len(clientIPs) > displayCount {
			fmt.Printf("\n... and %d more client(s)\n", len(clientIPs)-displayCount)
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("Press Ctrl+C to stop monitoring")
	fmt.Println(strings.Repeat("=", 80))
}

// clearScreen clears the terminal screen
func clearScreen() {
	switch runtime.GOOS {
	case "linux", "darwin":
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	case "windows":
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	default:
		// Fallback: print newlines
		fmt.Print("\033[H\033[2J")
	}
}

// centerText centers text within a given width
func centerText(text string, width int) string {
	if len(text) >= width {
		return text
	}
	padding := (width - len(text)) / 2
	return strings.Repeat(" ", padding) + text
}

// formatDuration formats a duration into a readable string
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

// formatPorts formats a list of ports
func formatPorts(ports []uint16) string {
	if len(ports) == 0 {
		return "none"
	}
	if len(ports) <= 5 {
		var strs []string
		for _, port := range ports {
			strs = append(strs, fmt.Sprintf("%d", port))
		}
		return strings.Join(strs, ", ")
	}
	var strs []string
	for i := 0; i < 5; i++ {
		strs = append(strs, fmt.Sprintf("%d", ports[i]))
	}
	return strings.Join(strs, ", ") + fmt.Sprintf(", ... (+%d more)", len(ports)-5)
}
