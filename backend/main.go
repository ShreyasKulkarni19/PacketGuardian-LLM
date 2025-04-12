package main

import (
	"PacketGuardian-LLM/backend/handlers"
	"fmt"
	"log"
	"net/http"
)

func main() {
	// Define the upload endpoint
	http.HandleFunc("/upload", handlers.UploadHandler)

	// Start the server
	port := ":8080"
	fmt.Printf("Server running on port %s\n", port)
	log.Fatal(http.ListenAndServe(port, nil))
}
