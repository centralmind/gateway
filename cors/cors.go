package cors

import "net/http"

// ApplyCORSHeaders adds the standard CORS headers to a response
// For handlers that are not wrapped in middleware
func ApplyCORSHeaders(w http.ResponseWriter, allowedMethods string) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", allowedMethods+", OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, mcp-protocol-version")
}

// HandlePreflight checks if the request is a preflight OPTIONS request and handles it
// Returns true if the request was handled (caller should return immediately)
func HandlePreflight(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return true
	}
	return false
}
