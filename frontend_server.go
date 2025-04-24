package main

import (
	"log"
	"net/http"
)

func main() {
	// Define the directory to serve files from
	frontendDir := "./frontend"

	// Create a file server for the frontend directory
	fs := http.FileServer(http.Dir(frontendDir))

	// Serve static files at the root URL
	http.Handle("/", fs)

	// Start the server on port 3000
	log.Println("Frontend server running on http://localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", nil))
}
