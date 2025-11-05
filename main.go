//go:build linux
// +build linux

package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"wiredolphin/capture"
	"wiredolphin/logger"
	"wiredolphin/stats"
	"wiredolphin/ui"
)

func main() {
	// Check if running as root
	if os.Geteuid() != 0 {
		fmt.Println("Error: This program requires root privileges to capture raw packets.")
		fmt.Println("Please run with sudo:")
		fmt.Println("  sudo ./wiredolphin [interface]")
		os.Exit(1)
	}

	// Get interface name from command line or use default
	ifaceName := "tun0"
	if len(os.Args) > 1 {
		ifaceName = os.Args[1]
	}

	fmt.Printf("Starting Network Traffic Monitor on interface: %s\n", ifaceName)
	fmt.Println("Initializing...")

	// Initialize components
	globalStats := stats.NewGlobalStats()

	// Attempt to determine client subnets from the monitored interface (IPv4 and IPv6)
	if iface, err := net.InterfaceByName(ifaceName); err == nil {
		if addrs, err := iface.Addrs(); err == nil {
			var cidrs []*net.IPNet
			for _, a := range addrs {
				if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP != nil {
					cidrs = append(cidrs, ipNet)
				}
			}
			if len(cidrs) > 0 {
				globalStats.SetClientFilters(cidrs...)
			}
		}
	}

	csvLogger, err := logger.NewCSVLogger()
	if err != nil {
		fmt.Printf("Error creating CSV logger: %v\n", err)
		os.Exit(1)
	}
	defer csvLogger.Close()

	// Start periodic CSV flushing
	flushDone := make(chan struct{})
	csvLogger.StartPeriodicFlush(2*time.Second, flushDone)

	// Create packet capturer
	capturer, err := capture.NewCapturer(ifaceName, globalStats, csvLogger)
	if err != nil {
		fmt.Printf("Error creating capturer: %v\n", err)
		os.Exit(1)
	}
	defer capturer.Close()

	// Create TUI
	tui := ui.NewTUI(globalStats, ifaceName)

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Channel to signal goroutines to stop
	done := make(chan struct{})

	// Start packet capture in goroutine
	captureDone := make(chan error, 1)
	go func() {
		captureDone <- capturer.Start(done)
	}()

	// Start TUI in goroutine
	go tui.Start(done)

	// Wait for a few seconds before starting TUI to allow initialization
	time.Sleep(2 * time.Second)

	fmt.Println("Monitoring started. Press Ctrl+C to stop.")
	time.Sleep(1 * time.Second)

	// Wait for interrupt signal or capture error
	select {
	case <-sigChan:
		fmt.Println("\nReceived interrupt signal. Shutting down gracefully...")
	case err := <-captureDone:
		if err != nil {
			fmt.Printf("\nCapture error: %v\n", err)
		}
	}

	// Signal all goroutines to stop
	close(done)
	close(flushDone)

	// Give goroutines time to finish
	time.Sleep(500 * time.Millisecond)

	// Final flush and cleanup
	csvLogger.Flush()

	fmt.Println("Shutdown complete.")
	fmt.Printf("Total packets captured: %d\n", globalStats.TotalPackets)
	fmt.Printf("Total bytes: %s\n", stats.FormatBytes(globalStats.TotalBytes))
	fmt.Println("\nLog files created:")
	fmt.Println("  - camada_internet.csv")
	fmt.Println("  - camada_transporte.csv")
	fmt.Println("  - camada_aplicacao.csv")
}
