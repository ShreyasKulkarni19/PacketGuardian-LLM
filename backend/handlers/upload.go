package handlers

import (
	"PacketGuardian-LLM/backend/utils"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Store analysis results for PDF generation
var (
	analysisStore      = make(map[string]string)
	analysisStoreMutex sync.RWMutex
	lastAnalysisID     string

	// For storing progress updates
	progressUpdates     = make(map[string][]string)
	progressUpdateMutex sync.RWMutex
)

// ProgressUpdate represents a step in the analysis process
type ProgressUpdate struct {
	Step        string `json:"step"`
	Description string `json:"description"`
	Timestamp   int64  `json:"timestamp"`
}

func UploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form (max 10MB)
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("pcapFile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate file extension
	ext := filepath.Ext(handler.Filename)
	if ext != ".pcap" {
		http.Error(w, "Only .pcap files are allowed", http.StatusBadRequest)
		return
	}

	// Generate a unique ID for this analysis
	analysisID := fmt.Sprintf("analysis_%d", os.Getpid())

	// Initialize progress updates for this analysis
	progressUpdateMutex.Lock()
	progressUpdates[analysisID] = []string{
		"Starting analysis...",
		"Validating PCAP file format...",
	}
	progressUpdateMutex.Unlock()

	// Save file temporarily
	tempFile, err := os.CreateTemp("", "upload-*.pcap")
	if err != nil {
		http.Error(w, "Error creating temp file", http.StatusInternalServerError)
		return
	}
	defer tempFile.Close()
	defer os.Remove(tempFile.Name()) // Clean up after processing

	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}

	progressUpdateMutex.Lock()
	progressUpdates[analysisID] = append(progressUpdates[analysisID], "File uploaded successfully")
	progressUpdateMutex.Unlock()

	// Validate PCAP format
	if !utils.IsValidPCAP(tempFile.Name()) {
		http.Error(w, "Invalid PCAP file", http.StatusBadRequest)
		return
	}

	progressUpdateMutex.Lock()
	progressUpdates[analysisID] = append(progressUpdates[analysisID], "PCAP file validation complete")
	progressUpdates[analysisID] = append(progressUpdates[analysisID], "Starting packet analysis...")
	progressUpdateMutex.Unlock()

	// Process in a goroutine to allow sending back the analysis ID immediately
	go func() {
		// Real processing
		result := utils.ProcessPCAPWithUpdates(tempFile.Name(), analysisID, recordProgressUpdate)

		// Store the result for PDF generation
		analysisStoreMutex.Lock()
		analysisStore[analysisID] = result
		lastAnalysisID = analysisID
		analysisStoreMutex.Unlock()

		// Record final progress update
		recordProgressUpdate(analysisID, "Analysis complete. Report is ready for download.")
	}()

	// Send immediate response with the analysis ID
	responseData := map[string]interface{}{
		"status":     "processing",
		"analysisID": analysisID,
		"message":    "File uploaded successfully. Processing started.",
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(responseData)
}

// Helper function to record progress updates
func recordProgressUpdate(analysisID, update string) {
	progressUpdateMutex.Lock()
	defer progressUpdateMutex.Unlock()

	// Add the update to the list
	if _, exists := progressUpdates[analysisID]; !exists {
		progressUpdates[analysisID] = []string{}
	}

	progressUpdates[analysisID] = append(progressUpdates[analysisID], update)
}

// GetProgressHandler provides progress updates for a given analysis
func GetProgressHandler(w http.ResponseWriter, r *http.Request) {
	analysisID := r.URL.Query().Get("id")
	if analysisID == "" {
		http.Error(w, "Analysis ID is required", http.StatusBadRequest)
		return
	}

	progressUpdateMutex.RLock()
	updates, exists := progressUpdates[analysisID]
	progressUpdateMutex.RUnlock()

	if !exists {
		http.Error(w, "Analysis ID not found", http.StatusNotFound)
		return
	}

	// Check if analysis is complete
	analysisStoreMutex.RLock()
	result, analysisComplete := analysisStore[analysisID]
	analysisStoreMutex.RUnlock()

	var responseData map[string]interface{}

	if analysisComplete {
		// Parse result to extract detected threats and analysis
		if strings.Contains(result, "no threats detected") {
			responseData = map[string]interface{}{
				"status":          "complete",
				"threatsDetected": false,
				"packetCount":     extractPacketCount(result),
				"message":         result,
				"analysisID":      analysisID,
				"progressUpdates": updates,
			}
		} else {
			// Threats were detected
			threatsList := extractThreats(result)

			// Create a summary for display
			summary := generateSummary(result)

			responseData = map[string]interface{}{
				"status":          "complete",
				"threatsDetected": true,
				"packetCount":     extractPacketCount(result),
				"threats":         threatsList,
				"summary":         summary,
				"analysisID":      analysisID,
				"progressUpdates": updates,
			}
		}
	} else {
		// Analysis still in progress
		responseData = map[string]interface{}{
			"status":          "processing",
			"analysisID":      analysisID,
			"progressUpdates": updates,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(responseData)
}

// Helper function to generate a summary from the analysis
func generateSummary(result string) map[string]string {
	summary := make(map[string]string)

	// Extract the issue
	summary["issue"] = "Network security threat detected"

	// Find the analysis part
	analysisStart := strings.Index(result, "Analysis:")
	if analysisStart == -1 {
		summary["cause"] = "Unknown"
		summary["location"] = "Unknown"
		summary["solution"] = "Unknown"
		return summary
	}

	analysisText := result[analysisStart+len("Analysis:"):]

	// Look for typical patterns in the OpenAI analysis
	// For cause
	causeIndicators := []string{"caused by", "due to", "result of", "reason is"}
	for _, indicator := range causeIndicators {
		if idx := strings.Index(strings.ToLower(analysisText), indicator); idx != -1 {
			endIdx := idx + len(indicator) + 100 // Get about 100 chars after the indicator
			if endIdx > len(analysisText) {
				endIdx = len(analysisText)
			}

			// Find the end of the sentence
			sentenceEnd := strings.IndexAny(analysisText[idx:endIdx], ".!?")
			if sentenceEnd != -1 {
				sentenceEnd = idx + sentenceEnd + 1
			} else {
				sentenceEnd = endIdx
			}

			summary["cause"] = strings.TrimSpace(analysisText[idx:sentenceEnd])
			break
		}
	}

	// For location
	if strings.Contains(analysisText, "source IP") || strings.Contains(analysisText, "destination IP") {
		locStart := -1
		if idx := strings.Index(analysisText, "source IP"); idx != -1 {
			locStart = idx
		} else if idx := strings.Index(analysisText, "destination IP"); idx != -1 {
			locStart = idx
		}

		if locStart != -1 {
			endIdx := locStart + 50 // Get about 50 chars
			if endIdx > len(analysisText) {
				endIdx = len(analysisText)
			}

			// Find the end of the sentence
			sentenceEnd := strings.IndexAny(analysisText[locStart:endIdx], ".!?")
			if sentenceEnd != -1 {
				sentenceEnd = locStart + sentenceEnd + 1
			} else {
				sentenceEnd = endIdx
			}

			summary["location"] = strings.TrimSpace(analysisText[locStart:sentenceEnd])
		}
	}

	// For solution
	solutionIndicators := []string{"recommend", "should", "could", "prevent", "mitigate", "block"}
	for _, indicator := range solutionIndicators {
		if idx := strings.Index(strings.ToLower(analysisText), indicator); idx != -1 {
			endIdx := idx + 150 // Get a larger context for solutions
			if endIdx > len(analysisText) {
				endIdx = len(analysisText)
			}

			// Find the end of the sentence
			sentenceEnd := strings.IndexAny(analysisText[idx:endIdx], ".!?")
			if sentenceEnd != -1 {
				sentenceEnd = idx + sentenceEnd + 1
			} else {
				sentenceEnd = endIdx
			}

			summary["solution"] = strings.TrimSpace(analysisText[idx:sentenceEnd])
			break
		}
	}

	// Default values if not found
	if _, ok := summary["cause"]; !ok {
		summary["cause"] = "Suspicious network activity detected"
	}

	if _, ok := summary["location"]; !ok {
		summary["location"] = "Check the detailed report for specific IP addresses and ports"
	}

	if _, ok := summary["solution"]; !ok {
		summary["solution"] = "Review the detailed report and consider blocking suspicious IPs"
	}

	return summary
}

// DownloadReportHandler serves PDF reports
func DownloadReportHandler(w http.ResponseWriter, r *http.Request) {
	// Get analysis ID from the query parameters
	analysisID := r.URL.Query().Get("id")

	// If not provided, use the last analysis ID
	if analysisID == "" {
		analysisStoreMutex.RLock()
		analysisID = lastAnalysisID
		analysisStoreMutex.RUnlock()

		// If still no ID, return an error
		if analysisID == "" {
			http.Error(w, "No analysis available", http.StatusBadRequest)
			return
		}
	}

	// Get the analysis result from the store
	analysisStoreMutex.RLock()
	result, ok := analysisStore[analysisID]
	analysisStoreMutex.RUnlock()

	if !ok {
		http.Error(w, "Analysis not found", http.StatusNotFound)
		return
	}

	// Generate PDF report
	pdfBytes, err := utils.GeneratePDFReport(result)
	if err != nil {
		http.Error(w, "Error generating PDF report: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Set headers for PDF download
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "attachment; filename=packet_analysis_report.pdf")

	// Write PDF to response
	w.Write(pdfBytes)
}

// Helper functions
// Helper function to extract packet count from result string
func extractPacketCount(result string) int {
	var count int
	_, err := fmt.Sscanf(result, "Processed %d packets", &count)
	if err != nil {
		return 0
	}
	return count
}

// Helper function to extract threats from result string
func extractThreats(result string) []string {
	// Look for the pattern "detected threats: [...]" in the result
	start := strings.Index(result, "detected threats: ")
	if start == -1 {
		return []string{}
	}

	start += len("detected threats: ")
	end := strings.Index(result[start:], "\n")
	if end == -1 {
		end = len(result[start:])
	}

	threatsPart := result[start : start+end]
	// Remove brackets and split by comma
	threatsPart = strings.Trim(threatsPart, "[]")
	threatsList := strings.Split(threatsPart, " ")

	// Clean up the threats list
	var cleanThreats []string
	for _, threat := range threatsList {
		threat = strings.Trim(threat, ", ")
		if threat != "" {
			cleanThreats = append(cleanThreats, threat)
		}
	}

	return cleanThreats
}

// Helper function to extract analysis from result string
func extractAnalysis(result string) string {
	// Look for the section after "Analysis:"
	start := strings.Index(result, "Analysis:")
	if start == -1 {
		return ""
	}

	return strings.TrimSpace(result[start+len("Analysis:"):])
}
