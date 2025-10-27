package logger

import (
	"encoding/csv"
	"fmt"
	"os"
	"sync"
	"time"

	"wiredolphin/stats"
)

// CSVLogger handles writing packet data to CSV files
type CSVLogger struct {
	internetFile      *os.File
	transportFile     *os.File
	applicationFile   *os.File
	internetWriter    *csv.Writer
	transportWriter   *csv.Writer
	applicationWriter *csv.Writer
	mu                sync.Mutex
}

// NewCSVLogger creates a new CSV logger
func NewCSVLogger() (*CSVLogger, error) {
	logger := &CSVLogger{}

	// Open internet layer CSV
	internetFile, err := os.Create("camada_internet.csv")
	if err != nil {
		return nil, fmt.Errorf("failed to create camada_internet.csv: %v", err)
	}
	logger.internetFile = internetFile
	logger.internetWriter = csv.NewWriter(internetFile)

	// Write header
	logger.internetWriter.Write([]string{
		"Timestamp",
		"Protocol",
		"Source IP",
		"Destination IP",
		"Protocol Number",
		"ICMP Info",
		"Total Bytes",
	})
	logger.internetWriter.Flush()

	// Open transport layer CSV
	transportFile, err := os.Create("camada_transporte.csv")
	if err != nil {
		internetFile.Close()
		return nil, fmt.Errorf("failed to create camada_transporte.csv: %v", err)
	}
	logger.transportFile = transportFile
	logger.transportWriter = csv.NewWriter(transportFile)

	// Write header
	logger.transportWriter.Write([]string{
		"Timestamp",
		"Protocol",
		"Source IP",
		"Source Port",
		"Destination IP",
		"Destination Port",
		"Total Bytes",
	})
	logger.transportWriter.Flush()

	// Open application layer CSV
	applicationFile, err := os.Create("camada_aplicacao.csv")
	if err != nil {
		internetFile.Close()
		transportFile.Close()
		return nil, fmt.Errorf("failed to create camada_aplicacao.csv: %v", err)
	}
	logger.applicationFile = applicationFile
	logger.applicationWriter = csv.NewWriter(applicationFile)

	// Write header
	logger.applicationWriter.Write([]string{
		"Timestamp",
		"Protocol",
		"Protocol Info",
	})
	logger.applicationWriter.Flush()

	return logger, nil
}

// LogPacket logs a packet to the appropriate CSV files
func (l *CSVLogger) LogPacket(pkt *stats.PacketInfo) {
	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := pkt.Timestamp.Format("2006-01-02 15:04:05.000")

	// Log to internet layer CSV
	if pkt.NetworkProto != "" {
		l.internetWriter.Write([]string{
			timestamp,
			pkt.NetworkProto,
			pkt.SrcIP,
			pkt.DstIP,
			fmt.Sprintf("%d", pkt.ProtocolNum),
			pkt.ICMPInfo,
			fmt.Sprintf("%d", pkt.Size),
		})
	}

	// Log to transport layer CSV
	if pkt.TransportProto != "" && (pkt.TransportProto == "TCP" || pkt.TransportProto == "UDP") {
		l.transportWriter.Write([]string{
			timestamp,
			pkt.TransportProto,
			pkt.SrcIP,
			fmt.Sprintf("%d", pkt.SrcPort),
			pkt.DstIP,
			fmt.Sprintf("%d", pkt.DstPort),
			fmt.Sprintf("%d", pkt.Size),
		})
	}

	// Log to application layer CSV
	if pkt.AppProto != "" && pkt.AppProto != "Other" {
		l.applicationWriter.Write([]string{
			timestamp,
			pkt.AppProto,
			pkt.AppInfo,
		})
	}
}

// Flush flushes all CSV writers
func (l *CSVLogger) Flush() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.internetWriter.Flush()
	l.transportWriter.Flush()
	l.applicationWriter.Flush()
}

// Close closes all CSV files
func (l *CSVLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.internetWriter.Flush()
	l.transportWriter.Flush()
	l.applicationWriter.Flush()

	var errs []error
	if err := l.internetFile.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := l.transportFile.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := l.applicationFile.Close(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing files: %v", errs)
	}
	return nil
}

// StartPeriodicFlush starts a goroutine that periodically flushes the CSV writers
func (l *CSVLogger) StartPeriodicFlush(interval time.Duration, done <-chan struct{}) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				l.Flush()
			case <-done:
				ticker.Stop()
				return
			}
		}
	}()
}
