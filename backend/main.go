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

	// Enable CORS
	handler := cors.Default().Handler(mux)

	// Start the server
	port := ":8080"
	fmt.Printf("Server running on port %s\n", port)
	log.Fatal(http.ListenAndServe(port, handler))
}
