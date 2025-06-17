package oauth

import (
	"github.com/centralmind/gateway/cors"
	"net/http"
)

// CORSMiddleware applies standard CORS headers to the response
func CORSMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cors.ApplyCORSHeaders(w, "GET, POST")
		if cors.HandlePreflight(w, r) {
			return
		}
		// Call the original handler
		handler.ServeHTTP(w, r)
	})
}
