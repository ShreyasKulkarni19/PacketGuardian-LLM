package utils

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"

)

// ProcessPCAP processes the PCAP file to detect potential threats
func ProcessPCAP(pcapFile string) string {
	if pcapFile == "" {
		return "Error: PCAP file path is empty"
	}

	// Open the pcap file
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return fmt.Sprintf("Error opening pcap file: %v", err)
	}
	defer handle.Close()

	// Create a new packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Initialize threat detection variables
	var packetCount int
	var threatDetected bool

	for packet := range packetSource.Packets() {
		packetCount++
		if detectSQLInjection(packet) {
			threatDetected = true
		}
		if detectXSS(packet) {
			threatDetected = true
		}
		if detectDoS(packet) {
			threatDetected = true
		}
		if detectMalware(packet) {
			threatDetected = true
		}
		if detectPhishing(packet) {
			threatDetected = true
		}
		if detectBruteForce(packet) {
			threatDetected = true
		}
	}

	if threatDetected {
		return fmt.Sprintf("Processed %d packets and detected threats", packetCount)
	}
	return fmt.Sprintf("Processed %d packets, no threats detected", packetCount)
}

// SQL Injection Detection
func detectSQLInjection(packet gopacket.Packet) bool {
	if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {
		payload := string(applicationLayer.Payload())
		// List of common SQL injection patterns (this can be expanded)
		injectionPatterns := []string{
			"' OR 1=1 --", "' OR 'a'='a", "' UNION SELECT", "DROP TABLE", "SELECT * FROM",
		}
		for _, pattern := range injectionPatterns {
			if containsInjection(payload, pattern) {
				fmt.Println("SQL Injection detected:", payload)
				return true
			}
		}
	}
	return false
}

// Cross-Site Scripting (XSS) Detection
func detectXSS(packet gopacket.Packet) bool {
	if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {
		payload := string(applicationLayer.Payload())
		// Look for script injections or suspicious JavaScript patterns
		xssPatterns := []string{
			"<script>", "alert(", "javascript:", "onerror=", "document.cookie",
		}
		for _, pattern := range xssPatterns {
			if containsInjection(payload, pattern) {
				fmt.Println("XSS attack detected:", payload)
				return true
			}
		}
	}
	return false
}

// Denial of Service (DoS) Detection
// A map to track SYN packet counts per source IP
var synCounts = make(map[string]int)
const synThreshold = 100 // You can adjust this based on your sensitivity needs

func detectDoS(packet gopacket.Packet) bool {
	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()

	if networkLayer == nil || transportLayer == nil {
		return false
	}

	ipLayer, ok := networkLayer.(*layers.IPv4)
	if !ok {
		return false
	}

	tcpLayer, ok := transportLayer.(*layers.TCP)
	if !ok {
		return false
	}

	if tcpLayer.SYN && !tcpLayer.ACK {
		srcIP := ipLayer.SrcIP.String()
		synCounts[srcIP]++

		if synCounts[srcIP] > synThreshold {
			fmt.Printf("Potential SYN flood DoS attack from: %s (SYN count: %d)\n", srcIP, synCounts[srcIP])
			return true
		}
	}

	return false
}

// Malware Detection
func detectMalware(packet gopacket.Packet) bool {
	if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {
		payload := string(applicationLayer.Payload())
		if containsInjection(payload, "malware") {
			fmt.Println("Malware detected:", payload)
			return true
		}
	}
	return false
}

// Phishing Detection
func detectPhishing(packet gopacket.Packet) bool {
	if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {
		payload := string(applicationLayer.Payload())
		// Check if the URL looks suspicious
		if containsInjection(payload, "fakebank.com") || containsInjection(payload, "phishingsite.com") {
			fmt.Println("Phishing site detected:", payload)
			return true
		}
	}
	return false
}

// Brute Force Attack Detection
func detectBruteForce(packet gopacket.Packet) bool {
	// Example: Check for multiple failed login attempts (POST requests with wrong passwords)
	if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {
		payload := string(applicationLayer.Payload())
		if containsInjection(payload, "password=incorrect") {
			fmt.Println("Brute force attempt detected:", payload)
			return true
		}
	}
	return false
}

// Helper function to check if the payload contains a specific pattern
func containsInjection(payload, pattern string) bool {
	return string(payload) == pattern
}
