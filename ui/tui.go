package ui

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"wiredolphin/stats"
)

// TUI handles terminal user interface
type TUI struct {
	stats *stats.GlobalStats
	iface string
	// paging/filtering
	clientPage int
	pageSize   int
	filter     string
	rotateSecs int
	lastRotate time.Time
	// interactive state
	mu             sync.Mutex
	selectedClient int
	remotePage     map[string]int
	remoteLast     map[string]time.Time
	inputStop      chan struct{}
	remotePageSize int
}

// NewTUI creates a new TUI
func NewTUI(globalStats *stats.GlobalStats, iface string) *TUI {
	// Read optional environment configuration
	pageSize := 0
	rotateSecs := 5
	filter := ""
	remotePageSize := 5
	if v := os.Getenv("TUI_PAGE_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			pageSize = n
		}
	}
	if v := os.Getenv("TUI_ROTATE_SECS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			rotateSecs = n
		}
	}
	filter = os.Getenv("TUI_CLIENT_FILTER")
	if v := os.Getenv("TUI_REMOTE_PAGE_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			remotePageSize = n
		}
	}

	return &TUI{
		stats:          globalStats,
		iface:          iface,
		pageSize:       pageSize,
		filter:         filter,
		rotateSecs:     rotateSecs,
		lastRotate:     time.Now(),
		remotePage:     make(map[string]int),
		remoteLast:     make(map[string]time.Time),
		inputStop:      make(chan struct{}),
		remotePageSize: remotePageSize,
	}
}

// Start starts the TUI update loop
func (t *TUI) Start(done <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			// rotate pages if configured
			if t.pageSize > 0 {
				if time.Since(t.lastRotate) >= time.Duration(t.rotateSecs)*time.Second {
					t.clientPage++
					t.lastRotate = time.Now()
				}
			}
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

		// Sort clients by IP and apply optional filter
		var clientIPs []string
		for ip := range snapshot.ClientStats {
			if t.filter != "" {
				if !strings.Contains(ip, t.filter) {
					continue
				}
			}
			clientIPs = append(clientIPs, ip)
		}
		sort.Strings(clientIPs)

		// Paging for clients (optional)
		totalClients := len(clientIPs)
		startIdx := 0
		endIdx := totalClients
		if t.pageSize > 0 && totalClients > 0 {
			pages := (totalClients + t.pageSize - 1) / t.pageSize
			page := t.clientPage % pages
			startIdx = page * t.pageSize
			endIdx = startIdx + t.pageSize
			if endIdx > totalClients {
				endIdx = totalClients
			}
			// Show page indicator
			fmt.Printf("Showing clients %d-%d of %d (page %d/%d)\n", startIdx+1, endIdx, totalClients, page+1, pages)
		}

		now := time.Now()
		for _, clientIP := range clientIPs[startIdx:endIdx] {
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

			totalRemotes := len(remotes)
			if totalRemotes == 0 {
				fmt.Println("  No remote hosts observed yet.")
				continue
			}

			rps := t.remotePageSize
			if rps <= 0 || rps >= totalRemotes {
				rps = totalRemotes
			}
			if rps == 0 {
				rps = 1
			}

			rpages := (totalRemotes + rps - 1) / rps
			rp := t.remotePage[client.IP]
			if rp >= rpages {
				rp = 0
			}

			if t.remotePageSize > 0 && totalRemotes > t.remotePageSize {
				last := t.remoteLast[client.IP]
				if last.IsZero() {
					t.remoteLast[client.IP] = now
				} else if now.Sub(last) >= time.Duration(t.rotateSecs)*time.Second {
					rp = (rp + 1) % rpages
					t.remotePage[client.IP] = rp
					t.remoteLast[client.IP] = now
				}
			} else {
				rp = 0
				t.remotePage[client.IP] = 0
				t.remoteLast[client.IP] = now
			}

			t.remotePage[client.IP] = rp
			rstart := rp * rps
			rend := rstart + rps
			if rend > totalRemotes {
				rend = totalRemotes
			}

			if totalRemotes > rps {
				fmt.Printf("  Showing remotes %d-%d of %d (page %d/%d)\n", rstart+1, rend, totalRemotes, rp+1, rpages)
			}

			for _, remote := range remotes[rstart:rend] {

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
				fmt.Printf("    Connections: %-6d\n", remote.host.Connections)
				fmt.Printf("    Packets:    Sent: %-6d  Received: %-6d  Total: %-6d\n",
					remote.host.PacketsSent, remote.host.PacketsReceived,
					remote.host.PacketsSent+remote.host.PacketsReceived)
				fmt.Printf("    Traffic:    Sent: %-10s  Received: %-10s  Total: %s\n",
					stats.FormatBytes(remote.host.BytesSent),
					stats.FormatBytes(remote.host.BytesReceived),
					stats.FormatBytes(remote.host.BytesSent+remote.host.BytesReceived))
				fmt.Println()
			}
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("Press Ctrl+C to stop monitoring")
	fmt.Println(strings.Repeat("=", 80))
}

// clearScreen clears the terminal screen
func clearScreen() {
	// Use ANSI escape sequences to refresh the screen. This works in most terminals
	// and is preserved in container logs as escape sequences.
	// Move cursor to top-left and clear screen.
	fmt.Print("\033[H\033[2J")
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
