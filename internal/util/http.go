package util

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

// HTTPResponse defines a common JSON response.
type HTTPResponse struct {
	Status string      `json:"status"`
	Value  interface{} `json:"value,omitempty"`
	Error  string      `json:"error,omitempty"`
}

// JSONResponse encodes a JSON Response object.
func JSONResponse(w http.ResponseWriter, d interface{}, statusCode int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	fmt.Fprintf(w, "%s", dj)
}

// ClientIP implements a best effort algorithm to return the real client IP, it parses
// X-Real-IP and X-Forwarded-For in order to work properly with reverse-proxies such us: nginx or haproxy.
// Use X-Forwarded-For before X-Real-Ip as nginx uses X-Real-Ip with the proxy's IP.
func ClientIP(r *http.Request) string {
	clientIP := r.Header.Get("X-Forwarded-For")
	clientIP = strings.TrimSpace(strings.Split(clientIP, ",")[0])
	if clientIP == "" {
		clientIP = strings.TrimSpace(r.Header.Get("X-Real-Ip"))
	}
	if clientIP != "" {
		return clientIP
	}
	if ip, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return ip
	}
	return ""
}

// HTTPGetSkipVerify performs an HTTP GET request, skipping the default client's verification of the
// server's certificate chain and host name. Safe only for localhost/testing as per
// (CWE-295): TLS InsecureSkipVerify set true.
/* #nosec */
func HTTPGetSkipVerify(url string) (*http.Response, error) {
	if !strings.HasPrefix(url, "https://localhost") {
		return nil, errors.New("skip verify only allowed to localhost")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	}}}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "error creating request")
	}
	var resp *http.Response
	if resp, err = client.Do(req); err != nil {
		return nil, errors.Wrap(err, "error communicating with ofte service")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("ofte validation error, response code %d", resp.StatusCode)
	}
	return resp, nil
}
