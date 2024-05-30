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

// ResolverIndex keeps track of the current resolver index
var ResolverIndex int

func rotateResolver(resolvers []string) string {
	resolver := resolvers[ResolverIndex]
	ResolverIndex = (ResolverIndex + 1) % len(resolvers)
	return resolver
}

// CheckDomain checks if the given domain is vulnerable based on the fingerprints.
func CheckDomain(domain string, fingerprints []fingerprints.Fingerprint, resolvers []string) (bool, *fingerprints.Fingerprint, error) {
	// Create a context with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Rotate resolver
	resolverAddress := rotateResolver(resolvers)

	// Create a resolver with the context
	resolver := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, resolverAddress)
		},
	}

	// Check DNS with timeout
	cname, err := resolver.LookupCNAME(ctx, domain)
	if err == nil {
		for _, fp := range fingerprints {
			for _, cnameEntry := range fp.CNAME {
				if strings.Contains(cname, cnameEntry) {
					return true, &fp, nil
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
		return false, nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, nil, err
	}

	for _, fp := range fingerprints {
		if fp.HTTPStatus != nil && resp.StatusCode == *fp.HTTPStatus {
			for _, fingerprint := range fp.Fingerprint {
				if strings.Contains(string(body), fingerprint) {
					return true, &fp, nil
				}
			}
		}
	}

	return false, nil, nil
}
