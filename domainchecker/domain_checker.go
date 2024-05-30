package domainchecker

import (
	"context"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/topscoder/subgomain/fingerprints"
)

// CheckDomain checks if the given domain is vulnerable based on the fingerprints.
func CheckDomain(domain string, fingerprints []fingerprints.Fingerprint) (bool, error) {
	// Create a context with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Create a resolver with the context
	resolver := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, "8.8.8.8:53")
		},
	}

	// Check DNS with timeout
	cname, err := resolver.LookupCNAME(ctx, domain)
	if err == nil {
		for _, fp := range fingerprints {
			for _, cnameEntry := range fp.CNAME {
				if strings.Contains(cname, cnameEntry) {
					return true, nil
				}
			}
		}
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 2 * time.Second,
	}

	// Make HTTP GET request with timeout
	req, err := http.NewRequest("GET", "http://"+domain, nil)
	if err != nil {
		return false, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	for _, fp := range fingerprints {
		if fp.HTTPStatus != nil && resp.StatusCode == *fp.HTTPStatus {
			for _, fingerprint := range fp.Fingerprint {
				if strings.Contains(string(body), fingerprint) {
					return true, nil
				}
			}
		}
	}

	return false, nil
}
