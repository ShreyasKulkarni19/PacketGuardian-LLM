package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/joho/godotenv"
	"github.com/sashabaranov/go-openai"
)

// ProcessPCAP processes the PCAP file to detect potential threats
func ProcessPCAP(pcapFile string) string {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovered from panic in ProcessPCAP: %v\n", r)
		}
	}()
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
	var detectedThreats []string // To store the types of threats detected

	for packet := range packetSource.Packets() {
		packetCount++
		if detectSQLInjection(packet) {
			detectedThreats = append(detectedThreats, "SQL Injection")
		}
		if detectXSS(packet) {
			detectedThreats = append(detectedThreats, "Cross-Site Scripting (XSS)")
		}
		if detectDoS(packet) {
			detectedThreats = append(detectedThreats, "Denial of Service (DoS)")
		}
		if detectMalware(packet) {
			detectedThreats = append(detectedThreats, "Malware")
		}
		if detectPhishing(packet) {
			detectedThreats = append(detectedThreats, "Phishing")
		}
		if detectBruteForce(packet) {
			detectedThreats = append(detectedThreats, "Brute Force Attack")
		}
	}

	if len(detectedThreats) > 0 {
		uniqueThreats := removeDuplicates(detectedThreats)
		analysis := analyze(pcapFile, uniqueThreats)
		return fmt.Sprintf("Processed %d packets and detected threats: %s\n\nAnalysis:\n%s", packetCount, formatThreats(uniqueThreats), analysis)
	}
	return fmt.Sprintf("Processed %d packets, no threats detected", packetCount)
}

func analyze(pcapFile string, threats []string) string {
	readableData, err := convertPCAPToReadableFormat(pcapFile)
	if err != nil {
		return fmt.Sprintf("Error converting PCAP file: %v", err)
	}

	// Process the saved chunks for analysis synchronously
	analysisResults := processChunksForAnalysis(threats)
	fmt.Println("Threat analysis completed:\n", analysisResults)

	// Include readableData and analysisResults in the response
	return fmt.Sprintf("File uploaded and processing completed. Readable data:\n%s\n\nAnalysis Results:\n%s", readableData, analysisResults)
}
func splitData(data []map[string]interface{}, chunkSize int) [][]map[string]interface{} {
	var chunks [][]map[string]interface{}
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	return chunks
}

// func convertPCAPToReadableFormat(pcapFile string) (string, error) {
// 	handle, err := pcap.OpenOffline(pcapFile)
// 	if err != nil {
// 		return "", fmt.Errorf("error opening pcap file: %v", err)
// 	}
// 	defer handle.Close()

// 	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
// 	var packets []map[string]interface{}

// 	for packet := range packetSource.Packets() {
// 		packetInfo := map[string]interface{}{
// 			"timestamp": packet.Metadata().Timestamp.String(),
// 			"layers":    []string{},
// 		}

// 		for _, layer := range packet.Layers() {
// 			packetInfo["layers"] = append(packetInfo["layers"].([]string), layer.LayerType().String())
// 		}

// 		if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {
// 			packetInfo["payload"] = string(applicationLayer.Payload())
// 		}

// 		packets = append(packets, packetInfo)
// 	}

// 	jsonData, err := json.MarshalIndent(packets, "", "  ")
// 	if err != nil {
// 		return "", fmt.Errorf("error converting packets to JSON: %v", err)
// 	}

// 	return string(jsonData), nil
// }

func convertPCAPToReadableFormat(pcapFile string) (string, error) {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return "", fmt.Errorf("error opening pcap file: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var maliciousPackets []map[string]interface{}

	for packet := range packetSource.Packets() {
		// Check if the packet is malicious using detection functions
		if detectSQLInjection(packet) || detectXSS(packet) || detectDoS(packet) ||
			detectMalware(packet) || detectPhishing(packet) || detectBruteForce(packet) {

			// Extract packet information
			packetInfo := map[string]interface{}{
				"timestamp": packet.Metadata().Timestamp.String(),
				"layers":    []string{},
			}

			for _, layer := range packet.Layers() {
				packetInfo["layers"] = append(packetInfo["layers"].([]string), layer.LayerType().String())
			}

			if appLayer := packet.ApplicationLayer(); appLayer != nil {
				packetInfo["payload"] = string(appLayer.Payload())
			} else {
				// Include raw packet data if no application layer
				packetInfo["raw_packet"] = fmt.Sprintf("%x", packet.Data())
			}

			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				packetInfo["src_port"] = tcp.SrcPort
				packetInfo["dst_port"] = tcp.DstPort
			}

			// Add the malicious packet to the list
			maliciousPackets = append(maliciousPackets, packetInfo)
		}
	}

	// If no malicious packets are found, return an appropriate message
	if len(maliciousPackets) == 0 {
		return "", fmt.Errorf("No malicious packets detected in the PCAP file")
	}

	// Split the malicious packets into chunks
	chunkSize := 10 // Adjust the chunk size as needed
	chunks := splitData(maliciousPackets, chunkSize)

	// Save each chunk to a separate file
	for i, chunk := range chunks {
		fileName := fmt.Sprintf("malicious_chunk_%d.json", i+1)
		chunkData, err := json.MarshalIndent(chunk, "", "  ")
		if err != nil {
			return "", fmt.Errorf("error marshaling chunk %d: %v", i+1, err)
		}

		err = os.WriteFile(fileName, chunkData, 0644)
		if err != nil {
			return "", fmt.Errorf("error writing chunk %d to file: %v", i+1, err)
		}
		fmt.Printf("Saved malicious chunk %d to file: %s\n", i+1, fileName)
	}

	// Return the full JSON data of malicious packets as a string
	fullData, err := json.MarshalIndent(maliciousPackets, "", "  ")
	if err != nil {
		return "", fmt.Errorf("error marshaling full data: %v", err)
	}

	return string(fullData), nil
}

// Analyze the readable data using OpenAI API
func analyzeWithOpenAI(chunkData string, threats []string) string {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
	apiKey := os.Getenv("OPENAI_API_KEY")

	if apiKey == "" {
		return "Error: OpenAI API key not set"
	}
	fmt.Println("OpenAI API Key loaded successfully")

	client := openai.NewClient(apiKey)
	ctx := context.Background()

	prompt := fmt.Sprintf("Analyze the following network traffic data and explain the detected threats (%s), their causes, and resolutions.:\n\n%s", strings.Join(threats, ", "), chunkData)

	resp, err := client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: openai.GPT4, // Use GPT-4 for better analysis
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleSystem,
				Content: "You are a cybersecurity expert.",
			},
			{
				Role:    openai.ChatMessageRoleUser,
				Content: prompt,
			},
		},
	})

	if err != nil {
		fmt.Printf("Error analyzing data with OpenAI: %v\n", err)
		return fmt.Sprintf("Error analyzing data with OpenAI: %v", err)
	}

	return resp.Choices[0].Message.Content
}

func processChunksForAnalysis(threats []string) string {
	chunkFiles, err := filepath.Glob("malicious_chunk_*.json") // Match all chunk files
	if err != nil {
		log.Fatalf("Error finding chunk files: %v", err)
	}

	var analysisResults []string

	for _, file := range chunkFiles {
		fmt.Printf("Processing file: %s\n", file)

		// Read the content of the chunk file
		chunkData, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("Error reading file %s: %v\n", file, err)
			continue
		}

		// Analyze the chunk with OpenAI
		analysis := analyzeWithOpenAI(string(chunkData), threats)
		analysisResults = append(analysisResults, fmt.Sprintf("Analysis for %s:\n%s", file, analysis))
	}

	// Combine all analysis results into a single string
	return strings.Join(analysisResults, "\n\n")
}

// Helper function to format the list of detected threats
func formatThreats(threats []string) string {
	return fmt.Sprintf("%v", threats)
}

// Helper function to remove duplicate threat types
func removeDuplicates(threats []string) []string {
	seen := make(map[string]bool)
	var unique []string
	for _, threat := range threats {
		if !seen[threat] {
			seen[threat] = true
			unique = append(unique, threat)
		}
	}
	return unique
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

		if synCounts[srcIP]%100 == 0 {
			fmt.Printf("Potential SYN flood DoS attack from: %s (SYN count: %d)\n", srcIP, synCounts[srcIP])
		}

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
