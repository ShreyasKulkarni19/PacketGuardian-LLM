package main

import (
	"PacketGuardian-LLM/backend/handlers"
	"fmt"
	"log"
	"net/http"

	"github.com/rs/cors"
)

func main() {
	mux := http.NewServeMux()

	// Define the upload endpoint
	mux.HandleFunc("/upload", handlers.UploadHandler)

	// Add PDF report download endpoint
	mux.HandleFunc("/download-report", handlers.DownloadReportHandler)

	// Add progress updates endpoint
	mux.HandleFunc("/progress", handlers.GetProgressHandler)

	// Configure CORS
	corsOptions := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"}, // Frontend URL
		AllowedMethods:   []string{"GET", "POST"},           // Allowed HTTP methods
		AllowedHeaders:   []string{"Content-Type"},          // Allowed headers
		AllowCredentials: true,                              // Allow credentials if needed
	})

	// Wrap the mux with the CORS handler
	handler := corsOptions.Handler(mux)

	// Start the server
	port := ":8080"
	fmt.Printf("Server running on port %s\n", port)
	log.Fatal(http.ListenAndServe(port, handler))
}
