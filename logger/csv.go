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
	if err := writeHeader(logger.internetWriter, "camada_internet.csv", []string{
		"Timestamp",
		"Protocol",
		"Source IP",
		"Destination IP",
		"Protocol Number",
		"ICMP Info",
		"Total Bytes",
	}); err != nil {
		internetFile.Close()
		return nil, err
	}

	// Open transport layer CSV
	transportFile, err := os.Create("camada_transporte.csv")
	if err != nil {
		internetFile.Close()
		return nil, fmt.Errorf("failed to create camada_transporte.csv: %v", err)
	}
	logger.transportFile = transportFile
	logger.transportWriter = csv.NewWriter(transportFile)
	if err := writeHeader(logger.transportWriter, "camada_transporte.csv", []string{
		"Timestamp",
		"Protocol",
		"Source IP",
		"Source Port",
		"Destination IP",
		"Destination Port",
		"Total Bytes",
	}); err != nil {
		internetFile.Close()
		transportFile.Close()
		return nil, err
	}

	// Open application layer CSV
	applicationFile, err := os.Create("camada_aplicacao.csv")
	if err != nil {
		internetFile.Close()
		transportFile.Close()
		return nil, fmt.Errorf("failed to create camada_aplicacao.csv: %v", err)
	}
	logger.applicationFile = applicationFile
	logger.applicationWriter = csv.NewWriter(applicationFile)
	if err := writeHeader(logger.applicationWriter, "camada_aplicacao.csv", []string{
		"Timestamp",
		"Protocol",
		"Protocol Info",
	}); err != nil {
		internetFile.Close()
		transportFile.Close()
		applicationFile.Close()
		return nil, err
	}

	return logger, nil
}

// LogPacket logs a packet to the appropriate CSV files
func (l *CSVLogger) LogPacket(pkt *stats.PacketInfo) {
	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := pkt.Timestamp.Format("2006-01-02 15:04:05.000")

	// Log to internet layer CSV
	if pkt.NetworkProto != "" {
		l.writeRecord(l.internetWriter, "camada_internet.csv", []string{
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
		l.writeRecord(l.transportWriter, "camada_transporte.csv", []string{
			timestamp,
			pkt.TransportProto,
			pkt.SrcIP,
			fmt.Sprintf("%d", pkt.SrcPort),
			pkt.DstIP,
			fmt.Sprintf("%d", pkt.DstPort),
			fmt.Sprintf("%d", pkt.Size),
		})
	}

	// Log to application layer CSV (including 'Other' to comply with requirement)
	if pkt.AppProto != "" {
		l.writeRecord(l.applicationWriter, "camada_aplicacao.csv", []string{
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

	flushWriter(l.internetWriter, "camada_internet.csv")
	flushWriter(l.transportWriter, "camada_transporte.csv")
	flushWriter(l.applicationWriter, "camada_aplicacao.csv")
}

// Close closes all CSV files
func (l *CSVLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	flushWriter(l.internetWriter, "camada_internet.csv")
	flushWriter(l.transportWriter, "camada_transporte.csv")
	flushWriter(l.applicationWriter, "camada_aplicacao.csv")

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

func (l *CSVLogger) writeRecord(writer *csv.Writer, label string, record []string) {
	if err := writer.Write(record); err != nil {
		fmt.Fprintf(os.Stderr, "wiredolphin: failed to write %s: %v\n", label, err)
		return
	}
	// Ensure record is flushed to underlying file so 'cat' can see it immediately
	writer.Flush()
	if err := writer.Error(); err != nil {
		fmt.Fprintf(os.Stderr, "wiredolphin: flush error for %s after write: %v\n", label, err)
	}
}

func writeHeader(writer *csv.Writer, label string, record []string) error {
	if err := writer.Write(record); err != nil {
		return fmt.Errorf("failed to write header for %s: %w", label, err)
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("failed to flush header for %s: %w", label, err)
	}
	return nil
}

func flushWriter(writer *csv.Writer, label string) {
	writer.Flush()
	if err := writer.Error(); err != nil {
		fmt.Fprintf(os.Stderr, "wiredolphin: flush error for %s: %v\n", label, err)
	}
}
