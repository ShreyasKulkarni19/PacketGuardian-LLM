package handlers

import (
	"PacketGuardian-LLM/backend/utils"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

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

	// Validate PCAP format
	if !utils.IsValidPCAP(tempFile.Name()) {
		http.Error(w, "Invalid PCAP file", http.StatusBadRequest)
		return
	}

	// Placeholder for processing
	result := utils.ProcessPCAP(tempFile.Name())

	// Send response
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": "success", "result": "%s"}`, result)
}
